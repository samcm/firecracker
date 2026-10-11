// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The bring-up hot set: the guest pages a fork child touched between resume and its first
//! exec.
//!
//! A child whose guest memory is imported lazily (MV_MAP_LAZY) starts with no page-table
//! entries for it; each first touch, by the guest through KVM or by this VMM, installs exactly
//! one order-0 entry (lazy views are VM_NOHUGEPAGE, and guest memory is locked on fault, not
//! populated). The present pages of the child's own guest mappings are therefore exactly the
//! pages its bring-up touched. A later child of the same lineage pre-faults them before
//! resume. The set is a hint: pre-faulting any page is correct, only its cost differs.
//!
//! A set over the caps keeps the pages touched first. Presence carries no order, so the order
//! is the marks: a mark records which pages are present (at guest ready), and the record that
//! follows keeps those before any touched since, each group in guest-physical order. A busy
//! child that touches more than a set can name still leaves its bring-up for the next child.
//!
//! A page is *written* when its mapping is exclusive: a lazily installed page stays the
//! version's folio, mapped by the version too, while a write leaves a private copy (or, where
//! the version has no page, a fresh one) mapped only here.
//!
//! Wire form (FPHS v1, little-endian): "FPHS", u32 version, u32 count, u32 pages_total, then
//! `count` entries of u64 gpa, u64 size, u32 flags, u32 reserved. Entries are page-aligned,
//! sorted, non-overlapping and coalesced only across equal flags.

use std::io;
use std::os::fd::BorrowedFd;

use vm_memory::{Address, GuestMemory, GuestMemoryRegion};

use crate::vstate::memory::GuestMemoryMmap;

/// Page size the set is expressed in: order-0 pages only.
pub const PAGE_SIZE: u64 = 4096;
/// The most pages a set may name (256 MiB). A larger set keeps its first pages.
pub const MAX_PAGES: u64 = 65536;
/// The most entries a set may have: its FPHS body (at most 49,168 bytes) fits one fcmem
/// datagram beside the BackingPlan fields. A set with more keeps its first pages.
pub const MAX_ENTRIES: usize = 2048;
/// Entry flag: the child wrote the page during bring-up.
pub const FLAG_WRITTEN: u32 = 1;

const MAGIC: [u8; 4] = *b"FPHS";
const WIRE_VERSION: u32 = 1;
const HEADER_BYTES: usize = 16;
const ENTRY_BYTES: usize = 24;

/// One run of guest pages with the same flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HotRange {
    /// Guest-physical address of the first page.
    pub gpa: u64,
    /// Length in bytes, a multiple of [`PAGE_SIZE`].
    pub size: u64,
    /// [`FLAG_WRITTEN`] or 0.
    pub flags: u32,
}

/// A validated hot set: sorted, non-overlapping, coalesced, at most [`MAX_PAGES`] pages in at
/// most [`MAX_ENTRIES`] entries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HotSet {
    ranges: Vec<HotRange>,
}

/// Why bytes are not an FPHS v1 hot set.
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum DecodeError {
    /// hot set is shorter than its header or entries
    Truncated,
    /// hot set has trailing bytes after its entries
    Trailing,
    /// hot set magic or version is not FPHS v1
    Identity,
    /// hot set entry {0} is empty, unaligned, has unknown flags or a nonzero reserved field
    Entry(usize),
    /// hot set entry {0} is out of order, overlaps, or should have been coalesced
    Order(usize),
    /// hot set names {0} pages, not its header's total or over the cap
    Total(u64),
    /// hot set has {0} entries, over the cap
    Entries(usize),
}

impl HotSet {
    /// The ranges, in guest-physical order.
    pub fn ranges(&self) -> &[HotRange] {
        &self.ranges
    }

    /// Pages named by the set.
    pub fn pages(&self) -> u64 {
        self.ranges.iter().map(|r| r.size / PAGE_SIZE).sum()
    }

    /// Builds a set from page-aligned ranges in any order, each inside one of `spans` (the
    /// guest-physical [start, end) of each memory region). Over [`MAX_ENTRIES`], bridges the
    /// smallest gaps between consecutive read-only ranges of one span: a bridged page is only
    /// read-prefaulted, never recorded as written, and never lies outside guest memory. `None`
    /// if that cannot bring the entries under the cap, or if the pages exceed [`MAX_PAGES`].
    /// Overlapping input is a caller bug.
    fn from_ranges(mut ranges: Vec<HotRange>, spans: &[(u64, u64)]) -> Option<Self> {
        ranges.sort_unstable_by_key(|r| r.gpa);
        let mut out: Vec<HotRange> = Vec::with_capacity(ranges.len());
        for range in ranges {
            match out.last_mut() {
                Some(last) if last.gpa + last.size == range.gpa && last.flags == range.flags => {
                    last.size += range.size;
                }
                _ => out.push(range),
            }
        }
        if out.len() > MAX_ENTRIES {
            let span_of = |gpa: u64| {
                spans
                    .iter()
                    .position(|&(start, end)| start <= gpa && gpa < end)
            };
            // Gap i lies between out[i] and out[i + 1]. Each bridge removes exactly one entry,
            // so the smallest gaps add the fewest untouched pages.
            let mut gaps: Vec<(u64, usize)> = out
                .windows(2)
                .enumerate()
                .filter(|(_, w)| {
                    w[0].flags == 0
                        && w[1].flags == 0
                        && span_of(w[0].gpa).is_some()
                        && span_of(w[0].gpa) == span_of(w[1].gpa)
                })
                .map(|(i, w)| (w[1].gpa - (w[0].gpa + w[0].size), i))
                .collect();
            let excess = out.len() - MAX_ENTRIES;
            if gaps.len() < excess {
                return None;
            }
            gaps.sort_unstable();
            let mut bridge = vec![false; out.len()];
            for &(_, i) in &gaps[..excess] {
                bridge[i] = true;
            }
            let mut merged: Vec<HotRange> = Vec::with_capacity(MAX_ENTRIES);
            let mut join = false;
            for (i, range) in out.into_iter().enumerate() {
                match merged.last_mut() {
                    Some(last) if join => last.size = range.gpa + range.size - last.gpa,
                    _ => merged.push(range),
                }
                join = bridge[i];
            }
            out = merged;
        }
        let set = HotSet { ranges: out };
        (set.pages() <= MAX_PAGES).then_some(set)
    }

    /// The set of the longest prefix of `pages` (one-page ranges in the order they should be
    /// kept, first touched first) that fits the caps. A set over the caps degrades to its first
    /// pages; it is never dropped.
    fn fit(pages: Vec<HotRange>, spans: &[(u64, u64)]) -> Self {
        if let Some(set) = Self::from_ranges(pages.clone(), spans) {
            return set;
        }
        // The empty prefix always fits; `pages` whole does not. Adding a page can merge two
        // entries as well as add one, so the largest prefix that fits is searched for, not
        // assumed unique.
        let (mut fits, mut over) = (Self::default(), pages.len());
        let mut lo = 0;
        while over - lo > 1 {
            let mid = lo + (over - lo) / 2;
            match Self::from_ranges(pages[..mid].to_vec(), spans) {
                Some(set) => (lo, fits) = (mid, set),
                None => over = mid,
            }
        }
        fits
    }

    /// The FPHS v1 bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_BYTES + self.ranges.len() * ENTRY_BYTES);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&WIRE_VERSION.to_le_bytes());
        out.extend_from_slice(&u32::try_from(self.ranges.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&u32::try_from(self.pages()).unwrap().to_le_bytes());
        for range in &self.ranges {
            out.extend_from_slice(&range.gpa.to_le_bytes());
            out.extend_from_slice(&range.size.to_le_bytes());
            out.extend_from_slice(&range.flags.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
        }
        out
    }

    /// Parses FPHS v1 bytes, refusing anything [`HotSet::encode`] would not produce.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let u32_at = |off: usize| u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let u64_at = |off: usize| u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        if bytes.len() < HEADER_BYTES {
            return Err(DecodeError::Truncated);
        }
        if bytes[..4] != MAGIC || u32_at(4) != WIRE_VERSION {
            return Err(DecodeError::Identity);
        }
        let count = u32_at(8) as usize;
        let total = u64::from(u32_at(12));
        if count > MAX_ENTRIES {
            return Err(DecodeError::Entries(count));
        }
        let want = HEADER_BYTES + count * ENTRY_BYTES;
        if bytes.len() < want {
            return Err(DecodeError::Truncated);
        }
        if bytes.len() > want {
            return Err(DecodeError::Trailing);
        }
        let mut ranges: Vec<HotRange> = Vec::with_capacity(count);
        let mut pages = 0u64;
        for index in 0..count {
            let off = HEADER_BYTES + index * ENTRY_BYTES;
            let range = HotRange {
                gpa: u64_at(off),
                size: u64_at(off + 8),
                flags: u32_at(off + 16),
            };
            if range.size == 0
                || !range.gpa.is_multiple_of(PAGE_SIZE)
                || !range.size.is_multiple_of(PAGE_SIZE)
                || range.flags & !FLAG_WRITTEN != 0
                || u32_at(off + 20) != 0
                || range.gpa.checked_add(range.size).is_none()
            {
                return Err(DecodeError::Entry(index));
            }
            if let Some(last) = ranges.last() {
                let end = last.gpa + last.size;
                if range.gpa < end || (range.gpa == end && range.flags == last.flags) {
                    return Err(DecodeError::Order(index));
                }
            }
            pages = pages.saturating_add(range.size / PAGE_SIZE);
            ranges.push(range);
        }
        if pages != total || pages > MAX_PAGES {
            return Err(DecodeError::Total(pages));
        }
        Ok(HotSet { ranges })
    }
}

/// One guest-memory region of this process: its guest-physical base, host address and length.
#[derive(Debug, Clone, Copy)]
pub struct HostRegion {
    /// Guest-physical address of the region.
    pub gpa: u64,
    /// Host virtual address of its mapping in this process.
    pub host: u64,
    /// Length in bytes, page-aligned.
    pub len: u64,
}

/// Why a hot set could not be recorded. Unavailability (an eager import, an old kernel, a set
/// over the caps) is not an error: it is `Ok(None)`.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum RecordError {
    /// RESIDENT failed on a guest region: {0}
    Resident(io::Error),
    /// RESIDENT refused a guest region as not anonymous memory, a geometry bug: {0:#x}
    NotAnonymous(u64),
}

/// The present pages of `regions` in this process, from RESIDENT in steps of at most 1 GiB, as
/// one-page ranges in guest-physical order: first those `mark` names (sorted guest-physical
/// addresses of an earlier record), then the rest, of which at most [`MAX_PAGES`] are kept,
/// since no more could ever fit a set. `Ok(None)` when the kernel predates RESIDENT. A region
/// the kernel refuses as non-anonymous is skipped and reported in `skipped`.
fn scan_regions(
    regions: &[HostRegion],
    handle: BorrowedFd<'_>,
    mark: &[u64],
    skipped: &mut Vec<RecordError>,
) -> Result<Option<(Vec<HotRange>, Vec<HotRange>)>, RecordError> {
    let step = super::memversion::MV_RESIDENT_MAX_LEN;
    let words_per_step = usize::try_from(step / PAGE_SIZE / 64).unwrap();
    let mut present = vec![0u64; words_per_step];
    let mut written = vec![0u64; words_per_step];
    let mut regions = regions.to_vec();
    regions.sort_unstable_by_key(|r| r.gpa);
    let (mut marked, mut later) = (Vec::new(), Vec::new());
    'regions: for region in &regions {
        let mut offset = 0;
        while offset < region.len {
            let len = (region.len - offset).min(step);
            match super::memversion::resident(handle, region.host + offset, len, &mut present, &mut written)
            {
                Ok(Some(_)) => {}
                Ok(None) => return Ok(None),
                Err(err) if err.raw_os_error() == Some(libc::EINVAL) => {
                    skipped.push(RecordError::NotAnonymous(region.gpa));
                    continue 'regions;
                }
                Err(err) => return Err(RecordError::Resident(err)),
            }
            let step_pages = len / PAGE_SIZE;
            for (word_index, word) in present.iter().enumerate() {
                let mut bits = *word;
                while bits != 0 {
                    let bit = u64::from(bits.trailing_zeros());
                    bits &= bits - 1;
                    let page = word_index as u64 * 64 + bit;
                    if page >= step_pages {
                        break;
                    }
                    let gpa = region.gpa + offset + page * PAGE_SIZE;
                    let is_written = written[word_index] & (1 << bit) != 0;
                    let range = HotRange {
                        gpa,
                        size: PAGE_SIZE,
                        flags: if is_written { FLAG_WRITTEN } else { 0 },
                    };
                    if mark.binary_search(&gpa).is_ok() {
                        marked.push(range);
                    } else if later.len() < MAX_PAGES as usize {
                        later.push(range);
                    }
                }
            }
            offset += len;
        }
    }
    Ok(Some((marked, later)))
}

/// The hot set of `regions` in this process. Over the caps it keeps the pages touched first:
/// those an earlier mark named, then the rest, each in guest-physical order (RESIDENT knows
/// no finer order). `Ok(None)` when the kernel predates RESIDENT.
pub fn record_regions(
    regions: &[HostRegion],
    handle: BorrowedFd<'_>,
    mark: &[u64],
    skipped: &mut Vec<RecordError>,
) -> Result<Option<HotSet>, RecordError> {
    let Some((mut pages, later)) = scan_regions(regions, handle, mark, skipped)? else {
        return Ok(None);
    };
    pages.extend(later);
    let spans: Vec<(u64, u64)> = regions.iter().map(|r| (r.gpa, r.gpa + r.len)).collect();
    Ok(Some(HotSet::fit(pages, &spans)))
}

/// The guest-physical addresses of the pages present in `regions` now, sorted, at most
/// [`MAX_PAGES`]: the mark a later [`record_regions`] keeps first. `Ok(None)` when the kernel
/// predates RESIDENT.
pub fn mark_regions(
    regions: &[HostRegion],
    handle: BorrowedFd<'_>,
    skipped: &mut Vec<RecordError>,
) -> Result<Option<Vec<u64>>, RecordError> {
    Ok(scan_regions(regions, handle, &[], skipped)?
        .map(|(_, pages)| pages.into_iter().map(|r| r.gpa).collect()))
}

/// This VM's guest memory as host regions, or `None` unless every version import in this
/// process was lazy: an eagerly imported page is present without having been touched.
fn host_regions(memory: &GuestMemoryMmap) -> Option<Vec<HostRegion>> {
    if !super::memversion::imported_only_lazily() {
        return None;
    }
    Some(
        memory
            .iter()
            .map(|region| HostRegion {
                gpa: region.start_addr().raw_value(),
                host: region.as_ptr() as u64,
                len: region.len(),
            })
            .collect(),
    )
}

/// The hot set of this VM's guest memory, keeping first the pages `mark` names. `Ok(None)`
/// ("unavailable") without a lazy import or RESIDENT.
pub fn record(
    memory: &GuestMemoryMmap,
    handle: BorrowedFd<'_>,
    mark: &[u64],
    skipped: &mut Vec<RecordError>,
) -> Result<Option<HotSet>, RecordError> {
    match host_regions(memory) {
        Some(regions) => record_regions(&regions, handle, mark, skipped),
        None => Ok(None),
    }
}

/// The pages of this VM's guest memory present now, as a mark for [`record`]. `Ok(None)`
/// without a lazy import or RESIDENT.
pub fn mark(
    memory: &GuestMemoryMmap,
    handle: BorrowedFd<'_>,
    skipped: &mut Vec<RecordError>,
) -> Result<Option<Vec<u64>>, RecordError> {
    match host_regions(memory) {
        Some(regions) => mark_regions(&regions, handle, skipped),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use super::*;

    const ANY: &[(u64, u64)] = &[(0, u64::MAX)];

    fn r(gpa: u64, pages: u64, flags: u32) -> HotRange {
        HotRange {
            gpa,
            size: pages * PAGE_SIZE,
            flags,
        }
    }

    #[test]
    fn coalesces_only_equal_flags_in_gpa_order() {
        let set = HotSet::from_ranges(
            vec![
                r(0x5000, 1, 0),
                r(0x0000, 1, 0),
                r(0x1000, 1, FLAG_WRITTEN),
                r(0x2000, 1, FLAG_WRITTEN),
                r(0x3000, 1, 0),
                r(0x4000, 1, 0),
                r(0x1_0000_0000, 1, 0),
            ],
            ANY,
        )
        .unwrap();
        assert_eq!(
            set.ranges(),
            &[
                r(0x0000, 1, 0),
                r(0x1000, 2, FLAG_WRITTEN),
                r(0x3000, 3, 0),
                r(0x1_0000_0000, 1, 0),
            ]
        );
        assert_eq!(set.pages(), 7);
    }

    #[test]
    fn from_ranges_refuses_over_the_page_cap() {
        assert!(HotSet::from_ranges(vec![r(0, MAX_PAGES, 0)], ANY).is_some());
        assert!(
            HotSet::from_ranges(
                vec![r(0, MAX_PAGES, 0), r(MAX_PAGES * PAGE_SIZE * 2, 1, 0)],
                ANY
            )
            .is_none()
        );
    }

    /// `pages` one-page ranges from `gpa` with `flags`.
    fn pages_at(gpa: u64, pages: u64, flags: impl Fn(u64) -> u32) -> Vec<HotRange> {
        (0..pages).map(|i| r(gpa + i * PAGE_SIZE, 1, flags(i))).collect()
    }

    #[test]
    fn over_the_page_cap_keeps_the_first_pages_in_touch_order() {
        // Touched first: 10 pages high in guest memory; then MAX_PAGES pages from 0. Kept: all
        // of the first, then the lowest of the rest up to the cap.
        let high = 1 << 40;
        let mut pages = pages_at(high, 10, |_| FLAG_WRITTEN);
        pages.extend(pages_at(0, MAX_PAGES, |_| 0));
        let set = HotSet::fit(pages, ANY);
        assert_eq!(
            set.ranges(),
            &[r(0, MAX_PAGES - 10, 0), r(high, 10, FLAG_WRITTEN)]
        );
        assert_eq!(set.pages(), MAX_PAGES);
    }

    #[test]
    fn over_the_entry_cap_keeps_the_first_pages_in_touch_order() {
        // A busy child: alternating written and read-only pages admit no bridge, 3 * MAX_ENTRIES
        // of them. Touched first, its bring-up: 100 pages above them all, also alternating and
        // starting written, so no read-only gap joins it to the busy pages either.
        let busy = pages_at(0, 3 * MAX_ENTRIES as u64, |i| u32::from(i % 2 == 1));
        let bring_up_at = 4 * MAX_ENTRIES as u64 * PAGE_SIZE;
        let bring_up = pages_at(bring_up_at, 100, |i| u32::from(i % 2 == 0));
        let set = HotSet::fit([bring_up.clone(), busy.clone()].concat(), ANY);
        assert_eq!(set.ranges().len(), MAX_ENTRIES);
        // The whole bring-up, then the lowest busy pages that fill the cap.
        assert_eq!(set.ranges()[MAX_ENTRIES - 100..], bring_up[..]);
        assert_eq!(set.ranges()[..MAX_ENTRIES - 100], busy[..MAX_ENTRIES - 100]);
        assert_eq!(HotSet::decode(&set.encode()).unwrap(), set);
        // A set that fits is kept whole, whatever the order.
        let small = [busy[10..20].to_vec(), bring_up[..5].to_vec()].concat();
        assert_eq!(
            HotSet::fit(small.clone(), ANY),
            HotSet::from_ranges(small, ANY).unwrap()
        );
    }

    /// `n` one-page ranges; `gap(i)` pages lie between range i and i + 1.
    fn spaced(n: usize, flags: impl Fn(usize) -> u32, gap: impl Fn(usize) -> u64) -> Vec<HotRange> {
        let mut gpa = 0;
        (0..n)
            .map(|i| {
                let range = r(gpa, 1, flags(i));
                gpa += (1 + gap(i)) * PAGE_SIZE;
                range
            })
            .collect()
    }

    #[test]
    fn over_the_entry_cap_bridges_the_smallest_read_only_gap() {
        let input = spaced(MAX_ENTRIES + 1, |_| 0, |i| if i == 100 { 1 } else { 2 });
        let set = HotSet::from_ranges(input.clone(), ANY).unwrap();
        assert_eq!(set.ranges().len(), MAX_ENTRIES);
        assert_eq!(set.ranges()[100], r(input[100].gpa, 3, 0));
        assert_eq!(set.ranges()[101], input[102]);
        assert_eq!(set.pages(), MAX_ENTRIES as u64 + 2);
        assert!(set.encode().len() <= 49_168);
    }

    #[test]
    fn bridging_never_widens_a_written_range_or_crosses_a_region() {
        // The smallest gap (after 100) borders a written page, the next smallest (after 7)
        // crosses into another region: the bridge goes to the first ordinary gap instead.
        let input = spaced(
            MAX_ENTRIES + 1,
            |i| if i == 100 { FLAG_WRITTEN } else { 0 },
            |i| match i {
                100 => 1,
                7 => 2,
                _ => 3,
            },
        );
        let boundary = input[8].gpa;
        let spans = [(0, boundary), (boundary, u64::MAX)];
        let set = HotSet::from_ranges(input.clone(), &spans).unwrap();
        assert_eq!(set.ranges().len(), MAX_ENTRIES);
        assert_eq!(set.ranges()[0], r(0, 5, 0));
        assert_eq!(set.ranges()[6..8], input[7..9]);
        assert_eq!(set.ranges()[99], r(input[100].gpa, 1, FLAG_WRITTEN));
    }

    #[test]
    fn from_ranges_refuses_over_the_entry_cap_without_a_bridgeable_gap() {
        // Alternating written and read-only pages: no two read-only ranges are consecutive.
        let alternating = spaced(MAX_ENTRIES + 1, |i| u32::from(i % 2 == 1), |_| 1);
        assert_eq!(HotSet::from_ranges(alternating, ANY), None);
        // A bridge that would push the pages over the cap drops the set too.
        let wide = spaced(MAX_ENTRIES + 1, |_| 0, |_| MAX_PAGES);
        assert_eq!(HotSet::from_ranges(wide, ANY), None);
    }

    #[test]
    fn wire_round_trip_and_exact_bytes() {
        let set =
            HotSet::from_ranges(vec![r(0x2000, 3, FLAG_WRITTEN), r(0x9000, 1, 0)], ANY).unwrap();
        let bytes = set.encode();
        let mut want = Vec::new();
        want.extend_from_slice(b"FPHS");
        want.extend_from_slice(&1u32.to_le_bytes());
        want.extend_from_slice(&2u32.to_le_bytes());
        want.extend_from_slice(&4u32.to_le_bytes());
        for (gpa, size, flags) in [(0x2000u64, 0x3000u64, 1u32), (0x9000, 0x1000, 0)] {
            want.extend_from_slice(&gpa.to_le_bytes());
            want.extend_from_slice(&size.to_le_bytes());
            want.extend_from_slice(&flags.to_le_bytes());
            want.extend_from_slice(&0u32.to_le_bytes());
        }
        assert_eq!(bytes, want);
        assert_eq!(HotSet::decode(&bytes).unwrap(), set);
        assert_eq!(
            HotSet::decode(&HotSet::default().encode()).unwrap(),
            HotSet::default()
        );
    }

    #[test]
    fn decode_refuses_what_encode_never_writes() {
        let good = HotSet::from_ranges(vec![r(0x2000, 3, FLAG_WRITTEN), r(0x9000, 1, 0)], ANY)
            .unwrap()
            .encode();
        let with = |off: usize, bytes: &[u8]| {
            let mut b = good.clone();
            b[off..off + bytes.len()].copy_from_slice(bytes);
            HotSet::decode(&b)
        };
        let e1 = HEADER_BYTES + ENTRY_BYTES; // second entry
        assert_eq!(HotSet::decode(&good[..15]), Err(DecodeError::Truncated));
        assert_eq!(
            with(8, &u32::try_from(MAX_ENTRIES + 1).unwrap().to_le_bytes()),
            Err(DecodeError::Entries(MAX_ENTRIES + 1))
        );
        assert_eq!(
            HotSet::decode(&good[..good.len() - 1]),
            Err(DecodeError::Truncated)
        );
        assert_eq!(
            HotSet::decode(&[good.as_slice(), &[0]].concat()),
            Err(DecodeError::Trailing)
        );
        assert_eq!(with(0, b"FPHT"), Err(DecodeError::Identity));
        assert_eq!(with(4, &2u32.to_le_bytes()), Err(DecodeError::Identity));
        assert_eq!(with(12, &5u32.to_le_bytes()), Err(DecodeError::Total(4)));
        assert_eq!(
            with(e1, &0x9800u64.to_le_bytes()),
            Err(DecodeError::Entry(1))
        );
        assert_eq!(
            with(e1 + 8, &0u64.to_le_bytes()),
            Err(DecodeError::Entry(1))
        );
        assert_eq!(
            with(e1 + 16, &2u32.to_le_bytes()),
            Err(DecodeError::Entry(1))
        );
        assert_eq!(
            with(e1 + 20, &1u32.to_le_bytes()),
            Err(DecodeError::Entry(1))
        );
        // Overlapping the first entry, and adjacent with equal flags (uncoalesced).
        assert_eq!(
            with(e1, &0x4000u64.to_le_bytes()),
            Err(DecodeError::Order(1))
        );
        assert_eq!(
            with(
                e1,
                &[
                    0x5000u64.to_le_bytes().as_slice(),
                    &0x1000u64.to_le_bytes(),
                    &1u32.to_le_bytes()
                ]
                .concat()
            ),
            Err(DecodeError::Order(1))
        );
        // Adjacent with different flags is valid.
        with(e1, &0x5000u64.to_le_bytes()).unwrap();
    }

    #[test]
    fn unavailable_without_a_lazy_import() {
        // This test process imported no version: guest memory touched here is present without
        // being a bring-up, so there is no hot set to report.
        let memory = crate::test_utils::single_region_mem(16 * 4096);
        memory.iter().for_each(|region| {
            // SAFETY: the first byte of a live region of this test's guest memory.
            unsafe { std::ptr::write_volatile(region.as_ptr(), 1) };
        });
        let device = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(record(&memory, device.as_fd(), &[], &mut Vec::new()).unwrap(), None);
        assert_eq!(mark(&memory, device.as_fd(), &mut Vec::new()).unwrap(), None);
    }

    /// Needs a kernel with MV_IOC_RESIDENT and /dev/memversion_v1 (its handle here). Skips
    /// elsewhere unless RAMET_REQUIRE_RESIDENT is set, which the kernel-qualified run sets.
    #[test]
    fn records_exactly_the_touched_pages_with_written_flags() {
        const A_PAGES: u64 = 2048; // 8 MiB: spans PMD boundaries
        const B_PAGES: u64 = 1024;
        let map = |pages: u64| {
            // SAFETY: a fresh private anonymous mapping owned by this test.
            let addr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    usize::try_from(pages * PAGE_SIZE).unwrap(),
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                    -1,
                    0,
                )
            };
            assert_ne!(addr, libc::MAP_FAILED);
            let len = usize::try_from(pages * PAGE_SIZE).unwrap();
            // SAFETY: the mapping above; only its huge-page policy changes, as for guest memory.
            let advised = unsafe { libc::madvise(addr, len, libc::MADV_NOHUGEPAGE) };
            assert_eq!(advised, 0);
            addr as u64
        };
        let (a, b) = (map(A_PAGES), map(B_PAGES));
        let read = |addr: u64, page: u64| {
            // SAFETY: inside a live mapping above.
            unsafe { std::ptr::read_volatile((addr + page * PAGE_SIZE) as *const u8) };
        };
        let write = |addr: u64, page: u64| {
            // SAFETY: inside a live mapping above.
            unsafe { std::ptr::write_volatile((addr + page * PAGE_SIZE + 7) as *mut u8, 1) };
        };
        read(a, 0); // zero page: present, not exclusive
        write(a, 1);
        read(a, 2);
        write(a, 511); // across the first PMD boundary: one written run
        write(a, 512);
        read(a, A_PAGES - 1);
        write(b, 0);
        read(b, 700);
        let regions = [
            HostRegion {
                gpa: 0,
                host: a,
                len: A_PAGES * PAGE_SIZE,
            },
            HostRegion {
                gpa: 0x1_0000_0000,
                host: b,
                len: B_PAGES * PAGE_SIZE,
            },
        ];
        let required = std::env::var_os("RAMET_REQUIRE_RESIDENT").is_some();
        let Ok(device) = std::fs::File::open("/dev/memversion_v1") else {
            assert!(!required, "no /dev/memversion_v1 on a kernel that must have it");
            eprintln!("skipped: no /dev/memversion_v1");
            return;
        };
        let mut skipped = Vec::new();
        let Some(set) = record_regions(&regions, device.as_fd(), &[], &mut skipped).unwrap() else {
            assert!(!required, "RESIDENT unavailable on a kernel that must have it");
            eprintln!("skipped: no MV_IOC_RESIDENT on this kernel");
            return;
        };
        assert!(skipped.is_empty(), "{skipped:?}");
        let p = |page: u64| page * PAGE_SIZE;
        assert_eq!(
            set.ranges(),
            &[
                r(p(0), 1, 0),
                r(p(1), 1, FLAG_WRITTEN),
                r(p(2), 1, 0),
                r(p(511), 2, FLAG_WRITTEN),
                r(p(A_PAGES - 1), 1, 0),
                r(0x1_0000_0000, 1, FLAG_WRITTEN),
                r(0x1_0000_0000 + p(700), 1, 0),
            ]
        );
        assert_eq!(HotSet::decode(&set.encode()).unwrap(), set);
        // A page touched after recording is in the next record, not this one.
        write(b, 701);
        assert_eq!(
            record_regions(&regions, device.as_fd(), &[], &mut skipped)
                .unwrap()
                .unwrap()
                .pages(),
            set.pages() + 1
        );
        // A busy child: marked now, it then touches pages in more entries than a set may have
        // (alternately written and read, so none can be bridged). Its record keeps every
        // marked page and fills the rest of the cap with the lowest of the new ones.
        const C_PAGES: u64 = 3 * MAX_ENTRIES as u64;
        let c = map(C_PAGES);
        let mut regions = regions.to_vec();
        regions.push(HostRegion {
            gpa: 0x2_0000_0000,
            host: c,
            len: C_PAGES * PAGE_SIZE,
        });
        let marked = mark_regions(&regions, device.as_fd(), &mut skipped)
            .unwrap()
            .unwrap();
        assert_eq!(marked.len() as u64, set.pages() + 1);
        for page in 0..C_PAGES {
            if page % 2 == 0 {
                write(c, page);
            } else {
                read(c, page);
            }
        }
        let busy = record_regions(&regions, device.as_fd(), &marked, &mut skipped)
            .unwrap()
            .unwrap();
        assert_eq!(busy.ranges().len(), MAX_ENTRIES);
        assert_eq!(busy.ranges()[MAX_ENTRIES - 1].gpa, 0x2_0000_0000 + p(MAX_ENTRIES as u64 - 9));
        let named = |gpa: u64| {
            busy.ranges()
                .iter()
                .any(|r| r.gpa <= gpa && gpa < r.gpa + r.size)
        };
        assert!(marked.iter().all(|&gpa| named(gpa)), "a marked page was dropped");
        assert!(skipped.is_empty(), "{skipped:?}");
    }
}
