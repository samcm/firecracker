// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]

use vm_memory::{GuestAddress, GuestRegionCollection};

use crate::vstate::memory::{GuestMemoryMmap, GuestRegionMmap, GuestRegionMmapExt};

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
    crate::vstate::memory::anonymous(regions).expect("Cannot create guest memory mapping")
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
