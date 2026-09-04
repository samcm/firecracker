// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};

use vm_memory::{GuestMemoryError, ReadVolatile, WriteVolatile};

use crate::vstate::memory::{GuestAddress, GuestMemory, GuestMemoryMmap};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SyncIoError {
    /// Flush: {0}
    Flush(std::io::Error),
    /// Seek: {0}
    Seek(std::io::Error),
    /// SyncAll: {0}
    SyncAll(std::io::Error),
    /// Transfer: {0}
    Transfer(GuestMemoryError),
}

#[derive(Debug)]
pub struct SyncFileEngine {
    file: File,
}

// SAFETY: `File` is send and ultimately a POD.
unsafe impl Send for SyncFileEngine {}

impl SyncFileEngine {
    pub fn from_file(file: File) -> SyncFileEngine {
        SyncFileEngine { file }
    }

    #[cfg(test)]
    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, SyncIoError> {
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(SyncIoError::Seek)?;
        mem.get_slice(addr, count as usize)
            .and_then(|mut slice| Ok(self.file.read_exact_volatile(&mut slice)?))
            .map_err(SyncIoError::Transfer)?;
        Ok(count)
    }

    pub fn write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, SyncIoError> {
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(SyncIoError::Seek)?;
        mem.get_slice(addr, count as usize)
            .and_then(|slice| Ok(self.file.write_all_volatile(&slice)?))
            .map_err(SyncIoError::Transfer)?;
        Ok(count)
    }

    pub fn flush(&mut self) -> Result<(), SyncIoError> {
        // flush() first to force any cached data out of rust buffers.
        self.file.flush().map_err(SyncIoError::Flush)?;
        // Sync data out to physical media on host.
        self.file.sync_all().map_err(SyncIoError::SyncAll)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::test_utils::single_region_mem;

    /// Alignment `O_DIRECT` demands of the buffer address, the file offset and the length.
    const LOGICAL_BLOCK: u32 = 512;
    /// Knocks exactly one of those three out of alignment per case.
    const SKEW: u32 = 100;
    const MEM_LEN: usize = 8192;
    const FILE_LEN: u64 = 1 << 20;

    /// Host virtual address the engine will hand to `write(2)` for this guest range.
    fn host_address(mem: &GuestMemoryMmap, addr: GuestAddress, count: u32) -> usize {
        let slice = mem.get_slice(addr, count as usize).unwrap();
        slice.ptr_guard().as_ptr() as usize
    }

    fn assert_einval(case: &str, result: Result<u32, SyncIoError>) {
        match result {
            Err(SyncIoError::Transfer(GuestMemoryError::IOError(err))) => {
                assert_eq!(err.raw_os_error(), Some(libc::EINVAL), "{case}: {err}");
            }
            other => panic!("{case}: expected EINVAL from the engine, got {other:?}"),
        }
    }

    /// Filesystem magic of XFS, the only filesystem the measured alignment facts hold on.
    const XFS_SUPER_MAGIC: i128 = 0x5846_5342;

    /// The directory `FARPLANE_TEST_XFS_DIR` names, or `None` for the two skips it allows: no
    /// directory was named, or the XFS one named has no reflinks.
    fn reflink_dir() -> Option<PathBuf> {
        let Some(dir) = std::env::var_os("FARPLANE_TEST_XFS_DIR") else {
            eprintln!(
                "skipping: FARPLANE_TEST_XFS_DIR must name a directory on an XFS filesystem \
                 formatted with reflink=1"
            );
            return None;
        };
        let dir = PathBuf::from(dir);
        assert!(
            dir.is_dir(),
            "FARPLANE_TEST_XFS_DIR names {}, which is not an existing directory",
            dir.display()
        );
        let magic = filesystem_magic(&dir);
        assert_eq!(
            magic,
            XFS_SUPER_MAGIC,
            "FARPLANE_TEST_XFS_DIR names {}, whose filesystem magic is {magic:#x} and not XFS",
            dir.display()
        );

        // Both probe files are unlinked when they drop, whichever way the clone between them goes.
        let source = TempFile::new_in(&dir)
            .unwrap_or_else(|err| panic!("creating a probe file in {}: {err}", dir.display()));
        std::fs::write(source.as_path(), [0xa5u8; 4096])
            .unwrap_or_else(|err| panic!("writing a probe file in {}: {err}", dir.display()));
        let destination = TempFile::new_in(&dir)
            .unwrap_or_else(|err| panic!("creating a probe file in {}: {err}", dir.display()));

        // SAFETY: both arguments are descriptors the probe files hold open, and the return code
        // is checked.
        let cloned = unsafe {
            libc::ioctl(
                destination.as_file().as_raw_fd(),
                libc::FICLONE,
                source.as_file().as_raw_fd(),
            )
        };
        if cloned < 0 {
            let err = std::io::Error::last_os_error();
            assert_eq!(
                err.raw_os_error(),
                Some(libc::EOPNOTSUPP),
                "probing FICLONE in {}: {err}",
                dir.display()
            );
            eprintln!(
                "skipping: {} is on a filesystem that has no reflinks",
                dir.display()
            );
            return None;
        }
        Some(dir)
    }

    /// Filesystem magic of the filesystem `dir` lives on.
    fn filesystem_magic(dir: &std::path::Path) -> i128 {
        let path = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: `path` is NUL-terminated and outlives the call, and `stat` is a valid
        // allocation for a `libc::statfs`.
        let probed = unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) };
        assert_eq!(
            probed,
            0,
            "statfs {}: {}",
            dir.display(),
            std::io::Error::last_os_error()
        );
        // SAFETY: `statfs` returned success, so it initialized the whole struct.
        i128::from(unsafe { stat.assume_init() }.f_type)
    }

    #[test]
    fn test_direct_io_requires_512_alignment() {
        let Some(dir) = reflink_dir() else {
            return;
        };

        let backing = TempFile::new_in(&dir).unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_DIRECT)
            .open(backing.as_path())
            .unwrap_or_else(|err| {
                panic!(
                    "{} refused the O_DIRECT open every scratch descriptor carries: {err}",
                    dir.display()
                )
            });
        file.set_len(FILE_LEN).unwrap();

        let mem = single_region_mem(MEM_LEN);
        let mut engine = SyncFileEngine::from_file(file);

        // The region is one anonymous mmap based at a page boundary, so a guest offset shifts the
        // host virtual address the engine writes from by the same amount.
        let aligned = GuestAddress(0);
        let skewed = GuestAddress(u64::from(SKEW));
        let block = LOGICAL_BLOCK as usize;
        assert_eq!(host_address(&mem, aligned, LOGICAL_BLOCK) % block, 0);
        assert_eq!(
            host_address(&mem, skewed, LOGICAL_BLOCK) % block,
            SKEW as usize
        );

        let written = engine.write(0, &mem, aligned, LOGICAL_BLOCK).unwrap();
        assert_eq!(written, LOGICAL_BLOCK);

        assert_einval(
            "offset",
            engine.write(u64::from(SKEW), &mem, aligned, LOGICAL_BLOCK),
        );
        assert_einval(
            "length",
            engine.write(0, &mem, aligned, LOGICAL_BLOCK + SKEW),
        );
        assert_einval(
            "buffer address",
            engine.write(0, &mem, skewed, LOGICAL_BLOCK),
        );
    }
}
