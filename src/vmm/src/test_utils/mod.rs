// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]

use vm_memory::bitmap::NewBitmap;
use vm_memory::{GuestAddress, GuestRegionCollection};
use vmm_sys_util::tempdir::TempDir;

use crate::vstate::memory::{
    AtomicBitmap, GuestMemoryMmap, GuestRegionMmap, GuestRegionMmapExt, MmapRegionBuilder,
};

pub mod mock_resources;

/// Creates a [`GuestMemoryMmap`] with a single region of the given size starting at guest
/// physical address 0.
pub fn single_region_mem(region_size: usize) -> GuestMemoryMmap {
    single_region_mem_at(0, region_size)
}

pub fn single_region_mem_raw(region_size: usize) -> Vec<GuestRegionMmap> {
    single_region_mem_at_raw(0, region_size)
}

/// Creates a [`GuestMemoryMmap`] with a single region of the given size starting at the given
/// guest physical address `at`.
pub fn single_region_mem_at(at: u64, size: usize) -> GuestMemoryMmap {
    multi_region_mem(&[(GuestAddress(at), size)])
}

pub fn single_region_mem_at_raw(at: u64, size: usize) -> Vec<GuestRegionMmap> {
    multi_region_mem_raw(&[(GuestAddress(at), size)])
}

/// Creates anonymous, dirty-tracked, private mappings for the given regions.
fn anonymous_regions(regions: &[(GuestAddress, usize)]) -> Vec<GuestRegionMmap> {
    regions
        .iter()
        .map(|&(start, size)| {
            let flags = libc::MAP_NORESERVE | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
            let mapping =
                MmapRegionBuilder::new_with_bitmap(size, Some(AtomicBitmap::with_len(size)))
                    .with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
                    .with_mmap_flags(flags)
                    .build()
                    .expect("Cannot create guest memory mapping");

            GuestRegionMmap::new(mapping, start).expect("Cannot create guest memory region")
        })
        .collect()
}

/// Creates a [`GuestMemoryMmap`] with multiple regions, one KVM slot each.
pub fn multi_region_mem(regions: &[(GuestAddress, usize)]) -> GuestMemoryMmap {
    GuestRegionCollection::from_regions(
        anonymous_regions(regions)
            .into_iter()
            .zip(0u32..)
            .map(|(region, slot)| GuestRegionMmapExt::from_mmap_region(region, slot))
            .collect(),
    )
    .unwrap()
}

pub fn multi_region_mem_raw(regions: &[(GuestAddress, usize)]) -> Vec<GuestRegionMmap> {
    anonymous_regions(regions)
}

/// Creates a [`GuestMemoryMmap`] of the given size with the contained regions laid out in
/// accordance with the requirements of the architecture on which the tests are being run.
pub fn arch_mem(mem_size_bytes: usize) -> GuestMemoryMmap {
    multi_region_mem(&crate::arch::arch_memory_regions(mem_size_bytes))
}

pub fn arch_mem_raw(mem_size_bytes: usize) -> Vec<GuestRegionMmap> {
    multi_region_mem_raw(&crate::arch::arch_memory_regions(mem_size_bytes))
}

#[allow(clippy::undocumented_unsafe_blocks)]
#[allow(clippy::cast_possible_truncation)]
pub fn create_tmp_socket() -> (TempDir, String) {
    let tmp_dir = TempDir::new().unwrap();
    let tmp_dir_path_str = tmp_dir.as_path().to_str().unwrap();
    let tmp_socket_path = format!("{tmp_dir_path_str}/tmp_socket");

    unsafe {
        let socketfd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if socketfd < 0 {
            panic!("Cannot create socket");
        }
        let mut socket_addr = libc::sockaddr_un {
            sun_family: libc::AF_UNIX as u16,
            sun_path: [0; 108],
        };

        std::ptr::copy(
            tmp_socket_path.as_ptr().cast(),
            socket_addr.sun_path.as_mut_ptr(),
            tmp_socket_path.len(),
        );

        let bind = libc::bind(
            socketfd,
            (&socket_addr as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as u32,
        );
        if bind < 0 {
            panic!("Cannot bind socket");
        }

        let listen = libc::listen(socketfd, 1);
        if listen < 0 {
            panic!("Cannot listen on socket");
        }
    }

    (tmp_dir, tmp_socket_path)
}
