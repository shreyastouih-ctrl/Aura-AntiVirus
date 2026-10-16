use serde::{Deserialize, Serialize};

/// Number of min-hash values kept in a fingerprint.
pub const SIGNATURE_LEN: usize = 128;

/// A fuzzy fingerprint of a byte stream (MinHash over byte n-gram shingles).
///
/// Two files that differ only by inserted/reordered chunks still share many
/// shingles, so the estimated Jaccard similarity stays high. This is the
/// byte-level analogue of ssdeep/TLSH and is our polymorphic variant matcher.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FuzzyDigest {
    /// Sorted 32-bit minimum hashes.
    pub mins: Vec<u32>,
    pub length: u64,
}

impl FuzzyDigest {
    pub fn compute(data: &[u8]) -> Self {
        let mut heap: std::collections::BinaryHeap<u32> = std::collections::BinaryHeap::with_capacity(129);
        if data.len() >= WINDOW {
            for window in data.windows(WINDOW) {
                let h = hash_window(window);
                push_min(&mut heap, h);
            }
        } else {
            push_min(&mut heap, hash_window(data));
        }
        let mut mins: Vec<u32> = heap.into_vec();
        mins.sort_unstable();
        Self {
            mins,
            length: data.len() as u64,
        }
    }

    /// Estimated similarity in `0.0..=1.0` (1.0 == identical shingle sets).
    pub fn similarity(&self, other: &FuzzyDigest) -> f32 {
        if self.mins.is_empty() || other.mins.is_empty() {
            return 0.0;
        }
        let mut i = 0;
        let mut j = 0;
        let mut matched = 0usize;
        while i < self.mins.len() && j < other.mins.len() {
            match self.mins[i].cmp(&other.mins[j]) {
                std::cmp::Ordering::Equal => {
                    matched += 1;
                    i += 1;
                    j += 1;
                }
                std::cmp::Ordering::Less => i += 1,
                std::cmp::Ordering::Greater => j += 1,
            }
        }
        let union_estimate = self.mins.len() + other.mins.len() - matched;
        if union_estimate == 0 {
            0.0
        } else {
            matched as f32 / union_estimate as f32
        }
    }

    /// Convert similarity to an integer "distance" where lower is closer.
    pub fn distance(&self, other: &FuzzyDigest) -> u32 {
        ((1.0 - self.similarity(other)) * 100.0).round() as u32
    }
}

const WINDOW: usize = 4;
const KEEP: usize = 128;

fn hash_window(window: &[u8]) -> u32 {
    // Simple FNV-1a variant keeps this fast and dependency-light.
    let mut h: u32 = 0x811c_9dc5;
    for &b in window {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn push_min(heap: &mut std::collections::BinaryHeap<u32>, h: u32) {
    if heap.len() < KEEP {
        heap.push(h);
    } else if let Some(&max) = heap.peek() {
        if h < max {
            heap.pop();
            heap.push(h);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_inputs_are_identical() {
        let a = FuzzyDigest::compute(b"the quick brown fox jumps over the lazy dog");
        let b = FuzzyDigest::compute(b"the quick brown fox jumps over the lazy dog");
        assert_eq!(a.similarity(&b), 1.0);
    }

    #[test]
    fn mutated_variant_stays_similar() {
        let base: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
        let mut mutated = base.clone();
        // Overwrite a handful of bytes — simulating a polymorphic mutation.
        for i in (0..mutated.len()).step_by(200) {
            mutated[i] = mutated[i].wrapping_add(7);
        }
        let a = FuzzyDigest::compute(&base);
        let b = FuzzyDigest::compute(&mutated);
        assert!(a.similarity(&b) > 0.8, "sim={}", a.similarity(&b));
    }

    #[test]
    fn unrelated_inputs_are_dissimilar() {
        let a = FuzzyDigest::compute(&(0..4000u32).map(|i| (i % 251) as u8).collect::<Vec<_>>());
        let b = FuzzyDigest::compute(&(0..4000u32).map(|i| ((i * 7 + 3) % 251) as u8).rev().collect::<Vec<_>>());
        assert!(a.similarity(&b) < 0.5);
    }
}
