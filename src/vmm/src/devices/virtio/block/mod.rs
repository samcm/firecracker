// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::os::fd::RawFd;

use serde::{Deserialize, Serialize};

use self::virtio::VirtioBlockError;

pub mod device;
pub mod persist;
pub mod virtio;

/// Configuration options for disk caching.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum CacheType {
    /// Flushing mechanic not will be advertised to the guest driver
    #[default]
    Unsafe,
    /// Flushing mechanic will be advertised to the guest driver and
    /// flush requests coming from the guest will be performed using
    /// `fsync`.
    Writeback,
}

/// Number the jailer inherits the read-only root image at. It renumbers the descriptor to this
/// number on every launch, so it is where a restored root drive finds its backing store.
pub const ROOT_DESCRIPTOR_FILENO: RawFd = 4;

/// Number the jailer inherits the writable scratch descriptor at when the supervisor passes one.
/// The drive it backs is never the root device.
pub const SCRATCH_DESCRIPTOR_FILENO: RawFd = 5;

/// Errors the block device can trigger.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BlockError {
    /// Virtio backend error: {0}
    VirtioBackend(VirtioBlockError),
}

/// Stands the descriptors the jailer inherits up for the test binary: a sealed read-only image at
/// [`ROOT_DESCRIPTOR_FILENO`] and a read-write scratch disk at [`SCRATCH_DESCRIPTOR_FILENO`]. It
/// runs before `main`, so the reserved numbers are claimed before any test can be handed one.
#[cfg(test)]
#[used]
#[unsafe(link_section = ".init_array")]
static INHERIT_RESERVED_DESCRIPTORS: extern "C" fn() = inherit_reserved_descriptors;

#[cfg(test)]
extern "C" fn inherit_reserved_descriptors() {
    let image = disk_image(c"sealed-drive-image", libc::MFD_ALLOW_SEALING);

    // SAFETY: `image` is an owned memfd of this process, and sealing only restricts what it
    // permits.
    unsafe {
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        assert_eq!(
            libc::fcntl(image, libc::F_ADD_SEALS, seals),
            0,
            "F_ADD_SEALS"
        );
    }

    let link = std::ffi::CString::new(format!("/proc/self/fd/{image}")).unwrap();
    // SAFETY: `link` is a NUL-terminated string that outlives the call.
    let read_only = unsafe { libc::open(link.as_ptr(), libc::O_RDONLY) };
    assert!(read_only >= 0, "reopening the sealed image read-only");

    // A memfd is opened read-write, the access mode the scratch slot requires.
    let scratch = disk_image(c"scratch-disk", 0);

    // Both descriptors, and the ones they were duplicated from, stay open for the lifetime of the
    // process, exactly as a jailed Firecracker holds them.
    for (source, reserved) in [
        (read_only, ROOT_DESCRIPTOR_FILENO),
        (scratch, SCRATCH_DESCRIPTOR_FILENO),
    ] {
        // SAFETY: `source` is an owned descriptor and `dup2` rewrites this process' own table.
        assert!(unsafe { libc::dup2(source, reserved) } >= 0, "dup2");
    }
}

/// A memfd holding one page of disk image, opened read-write.
#[cfg(test)]
fn disk_image(name: &std::ffi::CStr, flags: libc::c_uint) -> RawFd {
    // SAFETY: `name` is a NUL-terminated string that outlives the call.
    let image = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), flags) };
    assert!(image >= 0, "memfd_create");
    let image = RawFd::try_from(image).unwrap();

    // SAFETY: `image` is an owned memfd of this process.
    assert_eq!(unsafe { libc::ftruncate(image, 0x1000) }, 0, "ftruncate");
    image
}
