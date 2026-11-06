// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The drive images a pre-started Firecracker receives at claim.
//!
//! Firecracker starts before the sandbox it will run is known, so the jailer cannot hand it the
//! sandbox's root image and scratch disk. The jailer instead reserves the two descriptor numbers
//! a drive is backed by, and pagemaster hands the images over in one `drives` frame. Every check
//! the jailer applied to an inherited image is applied here, before the image takes its slot.

use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};

use vmm_sys_util::syscall::SyscallReturnCode;

use crate::devices::virtio::block::{ROOT_DESCRIPTOR_FILENO, SCRATCH_DESCRIPTOR_FILENO};

const ROOT_IMAGE: &str = "the root image";
const SCRATCH_DISK: &str = "the scratch disk";

/// Filesystem magic of the internal shmem mount every memfd lives on.
const TMPFS_MAGIC: u64 = 0x0102_1994;
/// Filesystem magic of hugetlbfs, where a memfd created with `MFD_HUGETLB` lives.
const HUGETLBFS_MAGIC: u64 = 0x9584_58f6;
const REQUIRED_IMAGE_SEALS: libc::c_int =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
/// Permission bits that grant write access to an image, none of which a regular one may carry.
const IMAGE_WRITE_MODE_BITS: libc::mode_t = libc::S_IWUSR | libc::S_IWGRP | libc::S_IWOTH;
/// Bits that change the meaning of an inode beyond its permissions. A block device image is
/// neither a program to gain privileges from nor a directory, so all three are refused.
const IMAGE_SPECIAL_MODE_BITS: libc::mode_t = libc::S_ISUID | libc::S_ISGID | libc::S_ISVTX;

static INSTALLED: AtomicBool = AtomicBool::new(false);

/// A drive image handed over at claim is unusable for its slot.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DriveImageError {
    /// {0} must have a nonzero size
    ImageFdEmpty(&'static str),
    /// Failed to inspect {0}: {1}
    ImageFdInspect(&'static str, io::Error),
    /// {0} must be opened O_RDONLY
    ImageFdNotReadOnly(&'static str),
    /// {0} must be a regular file
    ImageFdNotRegularFile(&'static str),
    /// {0} is missing the write, grow, shrink or seal memfd seal
    ImageFdNotSealed(&'static str),
    /// {0} must not be owned by the jailed uid
    ImageFdOwnedByJailUid(&'static str),
    /// {0} must be a sealed memfd because Firecracker runs as uid 0
    ImageFdRegularFileAtRootUid(&'static str),
    /// {0} answers F_GET_SEALS but does not live on shmem or hugetlbfs
    ImageFdSealedNotShmem(&'static str),
    /// {0} must not have the setuid, setgid or sticky bit set
    ImageFdSpecialModeBits(&'static str),
    /// {0} must not have any write permission bit set
    ImageFdWritablePermissions(&'static str),
    /// {0} shares an inode with fd {1}, which is open for writing
    ImageFdWritableStreamAlias(&'static str, libc::c_int),
    /// The scratch disk must not name the root image inode
    ScratchFdAliasesRoot,
    /// {0} must not be opened O_APPEND
    ScratchFdAppend(&'static str),
    /// {0} must have a nonzero size
    ScratchFdEmpty(&'static str),
    /// Failed to inspect {0}: {1}
    ScratchFdInspect(&'static str, io::Error),
    /// {0} must be opened O_DIRECT
    ScratchFdNotDirect(&'static str),
    /// {0} must be opened O_RDWR
    ScratchFdNotReadWrite(&'static str),
    /// {0} must be a regular file
    ScratchFdNotRegularFile(&'static str),
    /// {0} must be a file on the node's filesystem, not on shmem or hugetlbfs
    ScratchFdSealingFilesystem(&'static str),
    /// The drive images were already installed
    AlreadyInstalled,
    /// Installing {0} into its slot failed: {1}
    Install(&'static str, io::Error),
}

/// Validates the images and moves them onto the descriptors drives are backed by: the root image
/// onto [`ROOT_DESCRIPTOR_FILENO`] and the scratch disk, when the sandbox has one, onto
/// [`SCRATCH_DESCRIPTOR_FILENO`]. This happens once per process.
pub fn install(root: OwnedFd, scratch: Option<OwnedFd>) -> Result<(), DriveImageError> {
    if INSTALLED.load(Ordering::Acquire) {
        return Err(DriveImageError::AlreadyInstalled);
    }
    // SAFETY: `geteuid` has no failure mode and no side effects.
    let uid = unsafe { libc::geteuid() };
    validate_image_fd(ROOT_IMAGE, root.as_raw_fd(), uid)?;
    if let Some(scratch) = &scratch {
        validate_scratch_fd(SCRATCH_DISK, scratch.as_raw_fd())?;
        reject_root_alias(root.as_raw_fd(), scratch.as_raw_fd())?;
    }
    place(ROOT_IMAGE, &root, ROOT_DESCRIPTOR_FILENO)?;
    // A sandbox without a disk keeps the jailer's read-only placeholder in the scratch slot, so
    // the slot never names another descriptor and a scratch drive configured on it is refused.
    if let Some(scratch) = &scratch {
        place(SCRATCH_DISK, scratch, SCRATCH_DESCRIPTOR_FILENO)?;
    }
    INSTALLED.store(true, Ordering::Release);
    Ok(())
}

/// Whether the drive images have been installed.
pub fn installed() -> bool {
    INSTALLED.load(Ordering::Acquire)
}

/// Atomically replaces the jailer's placeholder in `slot` with `image`. The slot is never closed
/// in between, so no descriptor this process opens concurrently can take its number.
fn place(name: &'static str, image: &OwnedFd, slot: RawFd) -> Result<(), DriveImageError> {
    // SAFETY: both arguments are descriptor numbers and the return code is checked.
    SyscallReturnCode(unsafe { libc::dup3(image.as_raw_fd(), slot, libc::O_CLOEXEC) })
        .into_empty_result()
        .map_err(|err| DriveImageError::Install(name, err))
}

/// Checks that `fd` is a descriptor the supervisor is contracted to pass: a readable, read-only,
/// non-empty regular file holding a block device image whose bytes the jail cannot change. The
/// image itself is never read here.
///
/// Two kinds of descriptor satisfy that contract, told apart by whether the inode answers
/// `F_GET_SEALS`:
///
/// * A sealed memfd proves immutability in the kernel. The seals hold for every descriptor to the
///   inode, so no process changes the bytes, and no process needs to be trusted not to.
/// * A regular file cannot prove that much. Byte stability of a regular image is the
///   responsibility of the node or cache owner that published it, and that responsibility is not
///   transferred to Firecracker by any check below. What it does prove is the part it owns:
///   the confined process cannot obtain write access to the inode, neither through the inherited
///   descriptor, nor by chmod'ing a file it owns, nor through a setuid or setgid transition. None
///   of that holds for a jail that keeps uid 0, which is why that jail is refused this arm.
fn validate_image_fd(flag: &'static str, fd: RawFd, jail_uid: u32) -> Result<(), DriveImageError> {
    // SAFETY: `F_GETFL` writes nothing and the return code is checked.
    let flags = SyscallReturnCode(unsafe { libc::fcntl(fd, libc::F_GETFL) })
        .into_result()
        .map_err(|err| DriveImageError::ImageFdInspect(flag, err))?;
    // An `O_PATH` descriptor reports an access mode of `O_RDONLY` while referring to the inode
    // without granting any read at all, so it is rejected explicitly.
    if flags & libc::O_PATH != 0 || flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(DriveImageError::ImageFdNotReadOnly(flag));
    }

    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat` is a valid, aligned, sufficiently sized allocation for a `libc::stat`.
    SyscallReturnCode(unsafe { libc::fstat(fd, stat.as_mut_ptr()) })
        .into_empty_result()
        .map_err(|err| DriveImageError::ImageFdInspect(flag, err))?;
    // SAFETY: `fstat` returned success, so it initialized the whole struct.
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(DriveImageError::ImageFdNotRegularFile(flag));
    }
    if stat.st_size == 0 {
        return Err(DriveImageError::ImageFdEmpty(flag));
    }

    // Every shmem and hugetlbfs inode answers `F_GET_SEALS`, memfd or not, and every other
    // filesystem fails it with EINVAL. That is what selects the arm: an image on tmpfs or
    // hugetlbfs is held to the sealed memfd contract even when it was created as an ordinary
    // file, so a plain tmpfs file is refused for the seals it does not carry.
    // SAFETY: `F_GET_SEALS` writes nothing and the return code is checked.
    match SyscallReturnCode(unsafe { libc::fcntl(fd, libc::F_GET_SEALS) }).into_result() {
        Ok(seals) => validate_sealed_image(flag, fd, seals),
        Err(err) if err.raw_os_error() == Some(libc::EINVAL) => {
            validate_unwritable_image(flag, &stat, jail_uid)
        }
        Err(err) => Err(DriveImageError::ImageFdInspect(flag, err)),
    }
}

/// Holds an image on a sealing filesystem to the memfd contract: the seals that make the bytes
/// unchangeable for every holder of the inode, plus the identity of the two filesystems a memfd
/// can live on.
fn validate_sealed_image(
    flag: &'static str,
    fd: RawFd,
    seals: libc::c_int,
) -> Result<(), DriveImageError> {
    // Seals only ever remove abilities, and a kernel with vm.memfd_noexec enabled adds
    // F_SEAL_EXEC by itself, so anything beyond the required set is accepted.
    if seals & REQUIRED_IMAGE_SEALS != REQUIRED_IMAGE_SEALS {
        return Err(DriveImageError::ImageFdNotSealed(flag));
    }

    // A memfd lives on the internal shmem mount or on hugetlbfs and nowhere else. Together with
    // the seals above this proves identity without procfs, which no jail is required to have.
    // Anything else that answers `F_GET_SEALS`, such as a file on a mounted tmpfs, reaches here
    // and is refused unless it carries the same seals.
    let mut fs_stat = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `fs_stat` is a valid, aligned, sufficiently sized allocation for a `libc::statfs`.
    SyscallReturnCode(unsafe { libc::fstatfs(fd, fs_stat.as_mut_ptr()) })
        .into_empty_result()
        .map_err(|err| DriveImageError::ImageFdInspect(flag, err))?;
    // SAFETY: `fstatfs` returned success, so it initialized the whole struct.
    let fs_stat = unsafe { fs_stat.assume_init() };
    // `f_type` is a signed word on some targets and an unsigned one on others, so both sides are
    // widened to a type that holds either representation exactly.
    let magic = i128::from(fs_stat.f_type);
    if magic != i128::from(TMPFS_MAGIC) && magic != i128::from(HUGETLBFS_MAGIC) {
        return Err(DriveImageError::ImageFdSealedNotShmem(flag));
    }

    Ok(())
}

/// Holds an ordinary regular image to the property Firecracker can enforce on it: the jailed uid
/// has no path to write access. That property only exists below root. A jail that keeps uid 0
/// keeps `CAP_DAC_OVERRIDE` and `CAP_FOWNER`, which defeat both the permission bits and the
/// ownership of the inode, so uid 0 is held to the sealed memfd arm instead. Below root, write
/// permission for anyone is refused outright rather than reasoned about, the setuid, setgid and
/// sticky bits are refused because an image is not a program and not a directory, and an image
/// the jail owns is refused because ownership carries the right to chmod it writable after this
/// check.
fn validate_unwritable_image(
    flag: &'static str,
    stat: &libc::stat,
    jail_uid: u32,
) -> Result<(), DriveImageError> {
    if jail_uid == 0 {
        return Err(DriveImageError::ImageFdRegularFileAtRootUid(flag));
    }
    if stat.st_mode & IMAGE_WRITE_MODE_BITS != 0 {
        return Err(DriveImageError::ImageFdWritablePermissions(flag));
    }
    if stat.st_mode & IMAGE_SPECIAL_MODE_BITS != 0 {
        return Err(DriveImageError::ImageFdSpecialModeBits(flag));
    }
    if stat.st_uid == jail_uid {
        return Err(DriveImageError::ImageFdOwnedByJailUid(flag));
    }

    reject_writable_stream_aliases(flag, stat)
}

/// Refuses a regular image that a descriptor surviving the exec also holds open for writing.
///
/// The checks above prove the jail cannot obtain write access through the inherited image
/// descriptor itself, nor through the permissions or the ownership of the inode. A second open file
/// description on the same inode is neither of those: it carries its own access mode, granted
/// before this process narrowed anything, and `fstat` on the image says nothing about it.
///
/// The standard streams are the whole set of descriptors that reach Firecracker without the jailer
/// choosing what they refer to: the jailer keeps them so the jailed process can log, and every
/// other descriptor the process holds is one it opened itself or received from pagemaster. So a
/// caller that points a standard stream at the image inode with an access mode that includes
/// writing is the one way a writable alias reaches the jail, and that is refused here.
///
/// Only the root image is held to this: the jail is meant to write the scratch disk.
fn reject_writable_stream_aliases(
    flag: &'static str,
    stat: &libc::stat,
) -> Result<(), DriveImageError> {
    for fd in libc::STDIN_FILENO..=libc::STDERR_FILENO {
        let mut alias = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `alias` is a valid, aligned, sufficiently sized allocation for a `libc::stat`.
        match SyscallReturnCode(unsafe { libc::fstat(fd, alias.as_mut_ptr()) }).into_empty_result()
        {
            Ok(()) => {}
            // A standard stream the caller left closed refers to no inode, so it aliases nothing.
            Err(err) if err.raw_os_error() == Some(libc::EBADF) => continue,
            Err(err) => return Err(DriveImageError::ImageFdInspect(flag, err)),
        }
        // SAFETY: `fstat` returned success, so it initialized the whole struct.
        let alias = unsafe { alias.assume_init() };
        if alias.st_dev != stat.st_dev || alias.st_ino != stat.st_ino {
            continue;
        }

        // SAFETY: `F_GETFL` writes nothing and the return code is checked.
        let flags = SyscallReturnCode(unsafe { libc::fcntl(fd, libc::F_GETFL) })
            .into_result()
            .map_err(|err| DriveImageError::ImageFdInspect(flag, err))?;
        // An `O_PATH` descriptor grants no access at all, whatever access mode it reports.
        if flags & libc::O_PATH == 0 && flags & libc::O_ACCMODE != libc::O_RDONLY {
            return Err(DriveImageError::ImageFdWritableStreamAlias(flag, fd));
        }
    }

    Ok(())
}

/// Checks that `fd` is the descriptor the supervisor is contracted to pass for the scratch disk:
/// a non-empty regular file on the node's filesystem, opened read-write for direct I/O. The inode
/// is meant to be writable by the jail, so no permission, ownership or mode bit is read.
fn validate_scratch_fd(flag: &'static str, fd: RawFd) -> Result<(), DriveImageError> {
    // SAFETY: `F_GETFL` writes nothing and the return code is checked.
    let flags = SyscallReturnCode(unsafe { libc::fcntl(fd, libc::F_GETFL) })
        .into_result()
        .map_err(|err| DriveImageError::ScratchFdInspect(flag, err))?;
    // An `O_PATH` descriptor reports an access mode of `O_RDONLY` while referring to the inode
    // without granting any access at all, so it is rejected explicitly.
    if flags & libc::O_PATH != 0 || flags & libc::O_ACCMODE != libc::O_RDWR {
        return Err(DriveImageError::ScratchFdNotReadWrite(flag));
    }
    // `O_APPEND` moves every write to the end of the file, wherever the guest aimed it.
    if flags & libc::O_APPEND != 0 {
        return Err(DriveImageError::ScratchFdAppend(flag));
    }

    let stat = inode_of(fd).map_err(|err| DriveImageError::ScratchFdInspect(flag, err))?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(DriveImageError::ScratchFdNotRegularFile(flag));
    }
    if stat.st_size == 0 {
        return Err(DriveImageError::ScratchFdEmpty(flag));
    }

    // Every shmem and hugetlbfs inode answers `F_GET_SEALS` and every other filesystem fails it
    // with EINVAL, so an answer means the disk is the node's memory and not its filesystem.
    // SAFETY: `F_GET_SEALS` writes nothing and the return code is checked.
    match SyscallReturnCode(unsafe { libc::fcntl(fd, libc::F_GET_SEALS) }).into_result() {
        Ok(_) => return Err(DriveImageError::ScratchFdSealingFilesystem(flag)),
        Err(err) if err.raw_os_error() == Some(libc::EINVAL) => {}
        Err(err) => return Err(DriveImageError::ScratchFdInspect(flag, err)),
    }

    // The guest's reads and writes reach the disk itself, so the host holds no second copy of a
    // sandbox's data in its page cache.
    if flags & libc::O_DIRECT == 0 {
        return Err(DriveImageError::ScratchFdNotDirect(flag));
    }

    Ok(())
}

/// Refuses a scratch descriptor that names the root image inode. A caller could open one inode
/// twice, read-only for the root slot and writable for the scratch slot, and the guest would
/// reach the immutable root image through the writes it makes to its own disk.
fn reject_root_alias(root_fd: RawFd, scratch_fd: RawFd) -> Result<(), DriveImageError> {
    let root = inode_of(root_fd).map_err(|err| DriveImageError::ImageFdInspect(ROOT_IMAGE, err))?;
    let scratch =
        inode_of(scratch_fd).map_err(|err| DriveImageError::ScratchFdInspect(SCRATCH_DISK, err))?;
    if root.st_dev == scratch.st_dev && root.st_ino == scratch.st_ino {
        return Err(DriveImageError::ScratchFdAliasesRoot);
    }

    Ok(())
}

/// The inode `fd` refers to.
fn inode_of(fd: RawFd) -> Result<libc::stat, io::Error> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat` is a valid, aligned, sufficiently sized allocation for a `libc::stat`.
    SyscallReturnCode(unsafe { libc::fstat(fd, stat.as_mut_ptr()) }).into_empty_result()?;
    // SAFETY: `fstat` returned success, so it initialized the whole struct.
    Ok(unsafe { stat.assume_init() })
}

#[cfg(test)]
mod tests;
