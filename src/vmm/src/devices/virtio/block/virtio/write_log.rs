// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The byte ranges a block device wrote to its backing file while a log was recording, so a
//! capture can clone the file before its freeze and, inside it, catch up only what changed.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// The block every recorded range is widened to, so `FICLONERANGE` accepts it.
pub const WRITE_LOG_BLOCK: u64 = 4096;

/// The written ranges of one recording, merged and widened to whole blocks.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WrittenRanges {
    /// Disjoint, non-adjacent `[start, end)` byte ranges, ascending.
    pub ranges: Vec<(u64, u64)>,
    /// More ranges or bytes were written than the log holds: only a whole clone is exact.
    pub overflowed: bool,
}

#[derive(Debug, Default)]
struct Ranges {
    /// start -> end, disjoint and non-adjacent.
    set: BTreeMap<u64, u64>,
    bytes: u64,
    overflowed: bool,
    max_ranges: usize,
    max_bytes: u64,
}

impl Ranges {
    fn insert(&mut self, start: u64, end: u64) {
        if self.overflowed {
            return;
        }
        let (mut start, mut end) = (start, end);
        // Absorb every range that overlaps or touches [start, end).
        let first = self
            .set
            .range(..=start)
            .next_back()
            .filter(|(_, e)| **e >= start)
            .map(|(s, _)| *s)
            .unwrap_or(start);
        let absorbed: Vec<(u64, u64)> =
            self.set.range(first..=end).map(|(s, e)| (*s, *e)).collect();
        for (s, e) in absorbed {
            self.set.remove(&s);
            self.bytes -= e - s;
            start = start.min(s);
            end = end.max(e);
        }
        self.set.insert(start, end);
        self.bytes += end - start;
        if self.set.len() > self.max_ranges || self.bytes > self.max_bytes {
            self.overflowed = true;
            self.set.clear();
            self.bytes = 0;
        }
    }
}

/// A write log a block device feeds and a capture drains. Off, a write costs one atomic load.
///
/// A write is recorded when it completes, after its data is in the file. So a recording started
/// before a whole-file clone misses nothing: a write that completed before the start is in the
/// file the clone copies, and one that completes after it is recorded.
#[derive(Debug, Default)]
pub struct WriteLog {
    recording: AtomicBool,
    ranges: Mutex<Ranges>,
}

impl WriteLog {
    /// Starts a fresh recording that overflows past `max_ranges` merged ranges or `max_bytes`.
    pub fn start(&self, max_ranges: usize, max_bytes: u64) {
        let mut ranges = self.ranges.lock().expect("Poisoned lock");
        *ranges = Ranges {
            max_ranges,
            max_bytes,
            ..Ranges::default()
        };
        self.recording.store(true, Ordering::SeqCst);
    }

    /// Records that `len` bytes at `offset` reached the file, if a recording is on.
    pub fn record(&self, offset: u64, len: u64) {
        if len == 0 || !self.recording.load(Ordering::SeqCst) {
            return;
        }
        let start = offset - offset % WRITE_LOG_BLOCK;
        let end = offset
            .saturating_add(len)
            .checked_next_multiple_of(WRITE_LOG_BLOCK)
            .unwrap_or(u64::MAX);
        let mut ranges = self.ranges.lock().expect("Poisoned lock");
        // A recording stopped while this write waited for the lock records nothing.
        if self.recording.load(Ordering::SeqCst) {
            ranges.insert(start, end);
        }
    }

    /// Ends the recording and returns what it holds.
    pub fn take(&self) -> WrittenRanges {
        let mut ranges = self.ranges.lock().expect("Poisoned lock");
        self.recording.store(false, Ordering::SeqCst);
        let taken = WrittenRanges {
            ranges: ranges.set.iter().map(|(s, e)| (*s, *e)).collect(),
            overflowed: ranges.overflowed,
        };
        ranges.set.clear();
        ranges.bytes = 0;
        taken
    }

    /// Ends the recording and drops what it holds.
    pub fn stop(&self) {
        let _ = self.take();
    }

    /// Whether a recording is on.
    pub fn recording(&self) -> bool {
        self.recording.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_merge_into_whole_blocks_only_while_recording() {
        let log = WriteLog::default();
        log.record(0, 4096);
        assert_eq!(log.take(), WrittenRanges::default(), "nothing before start");
        log.start(16, 1 << 30);
        // Sub-block writes widen to whole blocks; adjacent and overlapping ranges merge.
        log.record(100, 10);
        log.record(4096, 4096);
        log.record(3 * 4096 + 1, 4096);
        log.record(10 * 4096, 1);
        log.record(9 * 4096, 4096);
        // A zero-length write records nothing.
        log.record(20 * 4096, 0);
        assert_eq!(
            log.take(),
            WrittenRanges {
                ranges: vec![(0, 2 * 4096), (3 * 4096, 5 * 4096), (9 * 4096, 11 * 4096)],
                overflowed: false,
            }
        );
        // take() ends the recording.
        log.record(0, 4096);
        assert!(!log.recording());
        assert_eq!(log.take(), WrittenRanges::default());
    }

    #[test]
    fn a_range_spanning_many_recorded_ones_absorbs_them() {
        let log = WriteLog::default();
        log.start(64, 1 << 30);
        for block in [1u64, 3, 5, 7] {
            log.record(block * 4096, 4096);
        }
        log.record(2 * 4096, 5 * 4096);
        log.record(9 * 4096, 4096);
        assert_eq!(
            log.take().ranges,
            vec![(4096, 8 * 4096), (9 * 4096, 10 * 4096)]
        );
    }

    #[test]
    fn past_its_bounds_the_log_overflows_and_holds_nothing() {
        let log = WriteLog::default();
        log.start(3, 1 << 30);
        for block in [0u64, 2, 4] {
            log.record(block * 4096, 4096);
        }
        // Merging into an existing range is not a new range.
        log.record(4096, 4096);
        assert!(!log.take().overflowed);
        log.start(3, 1 << 30);
        for block in [0u64, 2, 4, 6] {
            log.record(block * 4096, 4096);
        }
        assert_eq!(
            log.take(),
            WrittenRanges {
                ranges: vec![],
                overflowed: true,
            }
        );
        log.start(100, 8 * 4096);
        log.record(0, 8 * 4096);
        assert!(!log.take().overflowed);
        log.start(100, 8 * 4096);
        log.record(0, 8 * 4096 + 1);
        assert!(log.take().overflowed);
        // A new recording starts clean.
        log.start(100, 1 << 30);
        log.record(0, 1);
        assert_eq!(log.take().ranges, vec![(0, 4096)]);
    }

    #[test]
    fn random_writes_record_exactly_the_blocks_written() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200 {
            let log = WriteLog::default();
            log.start(1 << 20, u64::MAX);
            let mut blocks = [false; 512];
            for _ in 0..(next() % 64) {
                let offset = next() % (500 * 4096);
                let len = 1 + next() % (6 * 4096);
                log.record(offset, len);
                for b in offset / 4096..(offset + len).div_ceil(4096) {
                    blocks[usize::try_from(b).unwrap()] = true;
                }
            }
            let mut recorded = [false; 512];
            let taken = log.take();
            for pair in taken.ranges.windows(2) {
                assert!(pair[0].1 < pair[1].0, "ranges touch or overlap: {pair:?}");
            }
            for (s, e) in taken.ranges {
                for b in s / 4096..e / 4096 {
                    recorded[usize::try_from(b).unwrap()] = true;
                }
            }
            assert_eq!(recorded, blocks);
        }
    }
}
