// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::ops::Deref;

use kvm_bindings::{KVM_MEM_LOG_DIRTY_PAGES, kvm_userspace_memory_region};
use serde::{Deserialize, Serialize};
pub use vm_memory::bitmap::{AtomicBitmap, BS, Bitmap, BitmapSlice};
pub use vm_memory::mmap::MmapRegionBuilder;
pub use vm_memory::{
    Address, ByteValued, Bytes, FileOffset, GuestAddress, GuestMemory, GuestMemoryRegion,
    GuestUsize, MemoryRegionAddress, MmapRegion, address,
};
use vm_memory::{GuestMemoryRegionBytes, VolatileSlice};

use crate::utils::u64_to_usize;

/// Type of GuestRegionMmap.
pub type GuestRegionMmap = vm_memory::GuestRegionMmap<Option<AtomicBitmap>>;
/// Type of GuestMemoryMmap.
pub type GuestMemoryMmap = vm_memory::GuestRegionCollection<GuestRegionMmapExt>;
/// Type of GuestMmapRegion.
pub type GuestMmapRegion = vm_memory::MmapRegion<Option<AtomicBitmap>>;

/// Errors associated with guest memory.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MemoryError {
    /// Restored region ({addr}, {size}) does not match snapshot region ({want_addr}, {want_size})
    RegionMismatch {
        /// Guest address of the region handed over by the memory backend.
        addr: u64,
        /// Size in bytes of the region handed over by the memory backend.
        size: usize,
        /// Guest address recorded in the snapshot.
        want_addr: u64,
        /// Size in bytes recorded in the snapshot.
        want_size: usize,
    },
    /// Farplane memory channel failed: {0}
    Farplane(String),
}

/// An extension to GuestMemoryRegion which records the KVM memory slot the region is
/// registered under. Each region occupies exactly one slot.
#[derive(Debug)]
pub struct GuestRegionMmapExt {
    /// the wrapped GuestRegionMmap
    pub inner: GuestRegionMmap,
    /// the KVM slot number assigned to this region
    pub slot: u32,
}

impl From<&GuestRegionMmapExt> for kvm_userspace_memory_region {
    fn from(region: &GuestRegionMmapExt) -> Self {
        kvm_userspace_memory_region {
            // Every region carries a dirty bitmap, so dirty logging is always requested.
            flags: KVM_MEM_LOG_DIRTY_PAGES,
            slot: region.slot,
            guest_phys_addr: region.start_addr().raw_value(),
            memory_size: region.len(),
            userspace_addr: region.as_ptr() as u64,
        }
    }
}

impl GuestRegionMmapExt {
    pub(crate) fn from_mmap_region(region: GuestRegionMmap, slot: u32) -> Self {
        GuestRegionMmapExt {
            inner: region,
            slot,
        }
    }

    pub(crate) fn from_state(
        region: GuestRegionMmap,
        state: &GuestMemoryRegionState,
        slot: u32,
    ) -> Result<Self, MemoryError> {
        if region.start_addr().0 != state.base_address || u64_to_usize(region.len()) != state.size {
            return Err(MemoryError::RegionMismatch {
                addr: region.start_addr().0,
                size: u64_to_usize(region.len()),
                want_addr: state.base_address,
                want_size: state.size,
            });
        }

        Ok(Self::from_mmap_region(region, slot))
    }
}

impl Deref for GuestRegionMmapExt {
    type Target = MmapRegion<Option<AtomicBitmap>>;

    fn deref(&self) -> &MmapRegion<Option<AtomicBitmap>> {
        &self.inner
    }
}

impl GuestMemoryRegionBytes for GuestRegionMmapExt {}

#[allow(clippy::cast_possible_wrap)]
#[allow(clippy::cast_possible_truncation)]
impl GuestMemoryRegion for GuestRegionMmapExt {
    type B = Option<AtomicBitmap>;

    fn len(&self) -> GuestUsize {
        self.inner.len()
    }

    fn start_addr(&self) -> GuestAddress {
        self.inner.start_addr()
    }

    fn bitmap(&self) -> BS<'_, Self::B> {
        self.inner.bitmap()
    }

    fn get_host_address(
        &self,
        addr: MemoryRegionAddress,
    ) -> vm_memory::guest_memory::Result<*mut u8> {
        self.inner.get_host_address(addr)
    }

    fn file_offset(&self) -> Option<&FileOffset> {
        self.inner.file_offset()
    }

    fn get_slice(
        &self,
        offset: MemoryRegionAddress,
        count: usize,
    ) -> vm_memory::guest_memory::Result<VolatileSlice<'_, BS<'_, Self::B>>> {
        self.inner.get_slice(offset, count)
    }
}

/// Defines the interface for snapshotting memory.
pub trait GuestMemoryExtension
where
    Self: Sized,
{
    /// Describes GuestMemoryMmap through a GuestMemoryState struct.
    fn describe(&self) -> GuestMemoryState;

    /// Mark memory range as dirty
    fn mark_dirty(&self, addr: GuestAddress, len: usize);

    /// Resets all the memory region bitmaps
    fn reset_dirty(&self);
}

/// State of a guest memory region saved to file/buffer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestMemoryRegionState {
    // This should have been named `base_guest_addr` since it's _guest_ addr, but for
    // backward compatibility we have to keep this name. At least this comment should help.
    /// Base GuestAddress.
    pub base_address: u64,
    /// Region size.
    pub size: usize,
}

/// Describes guest memory regions and their snapshot file mappings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestMemoryState {
    /// List of regions.
    pub regions: Vec<GuestMemoryRegionState>,
}

impl GuestMemoryState {
    /// Turns this [`GuestMemoryState`] into a description of guest memory regions as understood
    /// by the creation functions of [`GuestMemoryExtensions`]
    pub fn regions(&self) -> impl Iterator<Item = (GuestAddress, usize)> + '_ {
        self.regions
            .iter()
            .map(|region| (GuestAddress(region.base_address), region.size))
    }
}

impl GuestMemoryExtension for GuestMemoryMmap {
    /// Describes GuestMemoryMmap through a GuestMemoryState struct.
    fn describe(&self) -> GuestMemoryState {
        let mut guest_memory_state = GuestMemoryState::default();
        self.iter().for_each(|region| {
            guest_memory_state.regions.push(GuestMemoryRegionState {
                base_address: region.start_addr().0,
                size: u64_to_usize(region.len()),
            });
        });
        guest_memory_state
    }

    /// Mark memory range as dirty
    fn mark_dirty(&self, addr: GuestAddress, len: usize) {
        // ignore invalid ranges using .flatten()
        for slice in self.get_slices(addr, len).flatten() {
            slice.bitmap().mark_dirty(0, slice.len());
        }
    }

    /// Resets all the memory region bitmaps
    fn reset_dirty(&self) {
        self.iter().for_each(|region| {
            if let Some(bitmap) = (**region).bitmap() {
                bitmap.reset();
            }
        })
    }
}

/// Test utilities
pub mod test_utils {
    use super::*;

    /// Converts a vec of GuestRegionMmap into a GuestMemoryMmap using GuestRegionMmapExt
    pub fn into_region_ext(regions: Vec<GuestRegionMmap>) -> GuestMemoryMmap {
        GuestMemoryMmap::from_regions(
            regions
                .into_iter()
                .zip(0u32..) // assign dummy slots
                .map(|(region, slot)| GuestRegionMmapExt::from_mmap_region(region, slot))
                .collect(),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::host_page_size;
    use crate::snapshot::Snapshot;
    use crate::test_utils::multi_region_mem_raw;
    use crate::vstate::memory::test_utils::into_region_ext;

    #[test]
    fn test_mark_dirty() {
        let page_size = host_page_size();
        let region_size = page_size * 3;

        let regions = [
            (GuestAddress(0), region_size),                      // pages 0-2
            (GuestAddress(region_size as u64), region_size),     // pages 3-5
            (GuestAddress(region_size as u64 * 2), region_size), // pages 6-8
        ];
        let guest_memory = into_region_ext(multi_region_mem_raw(&regions));

        let dirty_map = [
            // page 0: not dirty
            (0, page_size, false),
            // pages 1-2: dirty range in one region
            (page_size, page_size * 2, true),
            // page 3: not dirty
            (page_size * 3, page_size, false),
            // pages 4-7: dirty range across 2 regions,
            (page_size * 4, page_size * 4, true),
            // page 8: not dirty
            (page_size * 8, page_size, false),
        ];

        // Mark dirty memory
        for (addr, len, dirty) in &dirty_map {
            if *dirty {
                guest_memory.mark_dirty(GuestAddress(*addr as u64), *len);
            }
        }

        // Check that the dirty memory was set correctly
        for (addr, len, dirty) in &dirty_map {
            for slice in guest_memory
                .get_slices(GuestAddress(*addr as u64), *len)
                .flatten()
            {
                for i in 0..slice.len() {
                    assert_eq!(slice.bitmap().dirty_at(i), *dirty);
                }
            }
        }
    }

    fn check_serde<M: GuestMemoryExtension>(guest_memory: &M) {
        let original_state = guest_memory.describe();

        // Test direct bitcode serialization
        let serialized_data = bitcode::serialize(&original_state).unwrap();
        let restored_state: GuestMemoryState = bitcode::deserialize(&serialized_data).unwrap();
        assert_eq!(original_state, restored_state);

        // Test with Snapshot wrapper
        let snapshot_data = bitcode::serialize(&Snapshot::new(original_state.clone())).unwrap();
        let restored_snapshot = Snapshot::load_without_crc_check(&snapshot_data).unwrap();
        assert_eq!(original_state, restored_snapshot.data);
    }

    #[test]
    fn test_serde() {
        let page_size = host_page_size();
        let region_size = page_size * 3;

        // Test with a single region
        let guest_memory = into_region_ext(multi_region_mem_raw(&[(GuestAddress(0), region_size)]));
        check_serde(&guest_memory);

        // Test with some regions
        let regions = [
            (GuestAddress(0), region_size),                      // pages 0-2
            (GuestAddress(region_size as u64), region_size),     // pages 3-5
            (GuestAddress(region_size as u64 * 2), region_size), // pages 6-8
        ];
        let guest_memory = into_region_ext(multi_region_mem_raw(&regions));
        check_serde(&guest_memory);
    }

    #[test]
    fn test_describe() {
        let page_size: usize = host_page_size();

        // Two regions of one page each, with a one page gap between them.
        let mem_regions = [
            (GuestAddress(0), page_size),
            (GuestAddress(page_size as u64 * 2), page_size),
        ];
        let guest_memory = into_region_ext(multi_region_mem_raw(&mem_regions));

        let expected_memory_state = GuestMemoryState {
            regions: vec![
                GuestMemoryRegionState {
                    base_address: 0,
                    size: page_size,
                },
                GuestMemoryRegionState {
                    base_address: page_size as u64 * 2,
                    size: page_size,
                },
            ],
        };

        let actual_memory_state = guest_memory.describe();
        assert_eq!(expected_memory_state, actual_memory_state);

        // Two regions of three pages each, with a one page gap between them.
        let mem_regions = [
            (GuestAddress(0), page_size * 3),
            (GuestAddress(page_size as u64 * 4), page_size * 3),
        ];
        let guest_memory = into_region_ext(multi_region_mem_raw(&mem_regions));

        let expected_memory_state = GuestMemoryState {
            regions: vec![
                GuestMemoryRegionState {
                    base_address: 0,
                    size: page_size * 3,
                },
                GuestMemoryRegionState {
                    base_address: page_size as u64 * 4,
                    size: page_size * 3,
                },
            ],
        };

        let actual_memory_state = guest_memory.describe();
        assert_eq!(expected_memory_state, actual_memory_state);
    }

    #[test]
    fn test_from_state() {
        let page_size = host_page_size();

        let state = GuestMemoryRegionState {
            base_address: 0,
            size: page_size,
        };

        let region = multi_region_mem_raw(&[(GuestAddress(0), page_size)])
            .pop()
            .unwrap();
        let region = GuestRegionMmapExt::from_state(region, &state, 7).unwrap();
        let kvm_region = kvm_userspace_memory_region::from(&region);
        assert_eq!(kvm_region.slot, 7);
        assert_eq!(kvm_region.guest_phys_addr, 0);
        assert_eq!(kvm_region.memory_size, page_size as u64);
        assert_eq!(kvm_region.flags, KVM_MEM_LOG_DIRTY_PAGES);

        // A region whose size does not match the snapshot is rejected.
        let region = multi_region_mem_raw(&[(GuestAddress(0), page_size * 2)])
            .pop()
            .unwrap();
        assert!(matches!(
            GuestRegionMmapExt::from_state(region, &state, 0),
            Err(MemoryError::RegionMismatch { .. })
        ));

        // A region mapped at a different guest address than the snapshot is rejected.
        let region = multi_region_mem_raw(&[(GuestAddress(page_size as u64), page_size)])
            .pop()
            .unwrap();
        assert!(matches!(
            GuestRegionMmapExt::from_state(region, &state, 0),
            Err(MemoryError::RegionMismatch { .. })
        ));
    }
}
