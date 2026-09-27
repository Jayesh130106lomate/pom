//! Two-Epoch Rotating Bloom filter-based replay detection.
//!
//! Each relay maintains a rotating two-epoch Bloom filter system (F_current and F_previous)
//! to detect replayed packets both within an active epoch and across epoch boundaries.
//!
//! - Tag lookups (`might_contain`, `check_and_insert`) query both filters (F_current || F_previous).
//! - Insertions strictly write to F_current.
//! - On epoch rollover (`rollover` / `reset`), F_current is promoted to F_previous and a clean
//!   F_current is instantiated. This completely closes the epoch-rollover replay window.
//! - After two rollovers, tags from two epochs prior are cleanly retired.
//!
//! The packet "tag" is derived from the shared secret at that relay — the same
//! packet processed twice will produce the same tag, triggering replay detection.

use prism_crypto::kdf::hkdf_sha256;

/// Underlying single-epoch Bloom filter bit array.
#[derive(Clone, Debug)]
pub struct BloomFilter {
    /// Bit array.
    bits: Vec<u8>,
    /// Number of hash functions.
    k: usize,
    /// Total number of bits.
    m: usize,
    /// Number of items inserted.
    count: usize,
}

/// Derive Kirsch-Mitzenmacher double-hashing seeds (h1, h2) from a tag.
#[inline(always)]
pub fn derive_h1_h2(tag: &[u8; 32]) -> (u64, u64) {
    let hash_input = hkdf_sha256(tag, b"prism-bloom-km", b"double-hash", 16);
    let h1 = u64::from_be_bytes(hash_input[0..8].try_into().unwrap());
    let h2 = u64::from_be_bytes(hash_input[8..16].try_into().unwrap()) | 1;
    (h1, h2)
}

impl BloomFilter {
    /// Create a new Bloom filter with the given size in bytes and number of hash functions.
    pub fn new(size_bytes: usize, num_hashes: usize) -> Self {
        assert!(size_bytes > 0, "filter size in bytes must be > 0");
        assert!(num_hashes > 0, "number of hash functions must be > 0");
        BloomFilter {
            bits: vec![0u8; size_bytes],
            k: num_hashes,
            m: size_bytes * 8,
            count: 0,
        }
    }

    /// Compute hash positions for a given tag using Kirsch-Mitzenmacher double-hashing:
    /// g_i(x) = (h1(x) + i * h2(x)) mod m
    #[allow(dead_code)]
    fn hash_positions(&self, tag: &[u8; 32]) -> Vec<usize> {
        let (h1, h2) = derive_h1_h2(tag);
        let mut positions = Vec::with_capacity(self.k);
        for i in 0..self.k {
            let pos = (h1.wrapping_add((i as u64).wrapping_mul(h2)) as usize) % self.m;
            positions.push(pos);
        }
        positions
    }

    /// Check if a tag might be in the filter using precomputed (h1, h2) with zero heap allocations.
    #[inline(always)]
    pub fn might_contain_h(&self, h1: u64, h2: u64) -> bool {
        for i in 0..self.k {
            let pos = (h1.wrapping_add((i as u64).wrapping_mul(h2)) as usize) % self.m;
            let byte_idx = pos / 8;
            let bit_idx = pos % 8;
            if self.bits[byte_idx] & (1 << bit_idx) == 0 {
                return false;
            }
        }
        true
    }

    /// Insert into the filter using precomputed (h1, h2) with zero heap allocations.
    /// Returns true if all bits were already set (tag was present).
    #[inline(always)]
    pub fn insert_h(&mut self, h1: u64, h2: u64) -> bool {
        let mut was_present = true;
        for i in 0..self.k {
            let pos = (h1.wrapping_add((i as u64).wrapping_mul(h2)) as usize) % self.m;
            let byte_idx = pos / 8;
            let bit_idx = pos % 8;
            let mask = 1 << bit_idx;
            if self.bits[byte_idx] & mask == 0 {
                was_present = false;
            }
            self.bits[byte_idx] |= mask;
        }
        if !was_present {
            self.count += 1;
        }
        was_present
    }

    /// Check if a tag might be in the filter (may return false positives).
    pub fn might_contain(&self, tag: &[u8; 32]) -> bool {
        let (h1, h2) = derive_h1_h2(tag);
        self.might_contain_h(h1, h2)
    }

    /// Insert a tag into the filter.
    /// Returns true if the tag was already present (all bits set).
    pub fn insert(&mut self, tag: &[u8; 32]) -> bool {
        let (h1, h2) = derive_h1_h2(tag);
        self.insert_h(h1, h2)
    }

    /// Number of items inserted in this filter.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Size of the filter in bytes.
    pub fn size_bytes(&self) -> usize {
        self.bits.len()
    }

    /// Number of hash functions.
    pub fn num_hashes(&self) -> usize {
        self.k
    }

    /// Estimated false positive rate at current fill level:
    /// (1 - e^(-k * n / m))^k
    pub fn estimated_fpr(&self) -> f64 {
        let k = self.k as f64;
        let m = self.m as f64;
        let n = self.count as f64;
        (1.0 - (-k * n / m).exp()).powf(k)
    }

    /// Check whether the filter has exceeded an acceptable false positive rate threshold.
    pub fn is_saturated(&self, max_acceptable_fpr: f64) -> bool {
        self.estimated_fpr() >= max_acceptable_fpr
    }

    /// Clear all bits and reset count to zero.
    pub fn clear(&mut self) {
        self.bits.fill(0);
        self.count = 0;
    }
}

/// A rotating two-epoch Bloom filter system for detecting replayed Sphinx packet tags.
///
/// Contains two Bloom filters:
/// - `current`: Active filter for the current epoch, receives all new insertions.
/// - `previous`: Retained filter from the immediate predecessor epoch, queried during lookups.
///
/// Lookups query both filters (`current` || `previous`), while insertions strictly write to `current`.
/// On epoch rollover (`rollover` / `reset`), `current` is promoted to `previous` and a clean `current`
/// is instantiated. This completely closes the epoch-rollover replay window.
#[derive(Clone, Debug)]
pub struct ReplayFilter {
    current: BloomFilter,
    previous: BloomFilter,
    size_bytes: usize,
    num_hashes: usize,
}

impl ReplayFilter {
    /// Create a new rotating two-epoch Bloom filter system with the given size per epoch
    /// and number of hash functions.
    pub fn new(size_bytes: usize, num_hashes: usize) -> Self {
        ReplayFilter {
            current: BloomFilter::new(size_bytes, num_hashes),
            previous: BloomFilter::new(size_bytes, num_hashes),
            size_bytes,
            num_hashes,
        }
    }

    /// Create with default parameters (1 MB per epoch, 7 hash functions).
    /// Supports ~600K insertions per epoch at <1% false positive rate.
    pub fn default_for_epoch() -> Self {
        Self::new(crate::constants::BLOOM_FILTER_SIZE, crate::constants::BLOOM_HASH_COUNT)
    }

    /// Derive a packet tag from a shared secret.
    /// The tag is unique to this relay and this packet.
    pub fn derive_tag(shared_secret: &[u8; 32]) -> [u8; 32] {
        let tag_bytes = hkdf_sha256(shared_secret, b"prism-replay-tag", b"tag", 32);
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&tag_bytes);
        tag
    }

    /// Check if a tag might be in either the current or previous epoch filter.
    pub fn might_contain(&self, tag: &[u8; 32]) -> bool {
        let (h1, h2) = derive_h1_h2(tag);
        self.current.might_contain_h(h1, h2) || self.previous.might_contain_h(h1, h2)
    }

    /// Insert a tag into the current filter if not present in either filter.
    /// Returns true if the tag was already present in either current or previous filter (replay detected).
    pub fn insert(&mut self, tag: &[u8; 32]) -> bool {
        let (h1, h2) = derive_h1_h2(tag);
        if self.previous.might_contain_h(h1, h2) {
            return true;
        }
        self.current.insert_h(h1, h2)
    }

    /// Check and insert atomically — returns Err if replay detected.
    pub fn check_and_insert(&mut self, shared_secret: &[u8; 32]) -> Result<(), crate::SphinxError> {
        let tag = Self::derive_tag(shared_secret);
        if self.insert(&tag) {
            Err(crate::SphinxError::ReplayDetected)
        } else {
            Ok(())
        }
    }

    /// Number of items inserted in the current epoch filter.
    pub fn current_count(&self) -> usize {
        self.current.count()
    }

    /// Number of items inserted in the previous epoch filter.
    pub fn previous_count(&self) -> usize {
        self.previous.count()
    }

    /// Total items tracked across both current and previous epochs.
    pub fn count(&self) -> usize {
        self.current.count() + self.previous.count()
    }

    /// Size of each epoch filter in bytes.
    pub fn size_bytes(&self) -> usize {
        self.size_bytes
    }

    /// Number of hash functions.
    pub fn num_hashes(&self) -> usize {
        self.num_hashes
    }

    /// Estimated combined false positive rate across both filters:
    /// P(FP) = 1 - (1 - P(FP_current)) * (1 - P(FP_previous))
    pub fn estimated_fpr(&self) -> f64 {
        let fpr_curr = self.current.estimated_fpr();
        let fpr_prev = self.previous.estimated_fpr();
        1.0 - (1.0 - fpr_curr) * (1.0 - fpr_prev)
    }

    /// Check whether the combined filter system has exceeded an acceptable false positive rate threshold.
    pub fn is_saturated(&self, max_acceptable_fpr: f64) -> bool {
        self.estimated_fpr() >= max_acceptable_fpr
    }

    /// Perform epoch rollover:
    /// Promotes `current` -> `previous` and reinitializes `current` to a fresh empty state.
    /// Tags from the old `previous` are retired.
    pub fn rollover(&mut self) {
        std::mem::swap(&mut self.current, &mut self.previous);
        self.current.clear();
    }

    /// Alias for `rollover`.
    pub fn rollover_epoch(&mut self) {
        self.rollover();
    }

    /// Reset the filter system for a new epoch by performing epoch rollover.
    /// This closes the epoch-rollover replay window completely.
    pub fn reset(&mut self) {
        self.rollover();
    }

    /// Clear both current and previous filters completely (wipes all history).
    pub fn clear(&mut self) {
        self.current.clear();
        self.previous.clear();
    }

    /// Reference to the current epoch filter.
    pub fn current_filter(&self) -> &BloomFilter {
        &self.current
    }

    /// Reference to the previous epoch filter.
    pub fn previous_filter(&self) -> &BloomFilter {
        &self.previous
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_detection_basic() {
        let mut filter = ReplayFilter::new(1024, 5); // Small filter for testing
        let secret = [42u8; 32];

        // First insertion should succeed
        assert!(filter.check_and_insert(&secret).is_ok());

        // Second insertion should detect replay
        assert!(filter.check_and_insert(&secret).is_err());
    }

    #[test]
    fn test_in_epoch_replay_rejection() {
        let mut filter = ReplayFilter::new(8192, 7);
        let secret = [0xabu8; 32];

        // Initial insertion succeeds
        assert!(filter.check_and_insert(&secret).is_ok());
        assert_eq!(filter.current_count(), 1);
        assert_eq!(filter.previous_count(), 0);

        // Replay attempts within the same epoch are rejected
        for _ in 0..10 {
            assert!(matches!(
                filter.check_and_insert(&secret),
                Err(crate::SphinxError::ReplayDetected)
            ));
        }
        // Count must not increase on replay attempts
        assert_eq!(filter.current_count(), 1);
        assert_eq!(filter.previous_count(), 0);
    }

    #[test]
    fn different_secrets_no_collision() {
        let mut filter = ReplayFilter::new(8192, 7);

        for i in 0u8..100 {
            let mut secret = [0u8; 32];
            secret[0] = i;
            assert!(
                filter.check_and_insert(&secret).is_ok(),
                "false positive at i={}",
                i
            );
        }
    }

    #[test]
    fn replay_detection_after_many_inserts() {
        let mut filter = ReplayFilter::new(8192, 7);

        // Insert 100 different secrets
        let mut secrets = Vec::new();
        for i in 0u32..100 {
            let mut secret = [0u8; 32];
            secret[0..4].copy_from_slice(&i.to_be_bytes());
            filter.check_and_insert(&secret).unwrap();
            secrets.push(secret);
        }

        // Verify all 100 are detected as replays
        for secret in &secrets {
            assert!(filter.check_and_insert(secret).is_err());
        }
    }

    #[test]
    fn reset_clears_filter() {
        let mut filter = ReplayFilter::new(1024, 5);
        let secret = [7u8; 32];

        filter.check_and_insert(&secret).unwrap();
        assert!(filter.check_and_insert(&secret).is_err());

        // In rotating two-epoch filter, reset() performs rollover:
        // current is promoted to previous, closing the rollover replay window.
        filter.reset();
        assert_eq!(filter.current_count(), 0);
        assert_eq!(filter.previous_count(), 1);
        assert_eq!(filter.count(), 1);

        // After reset (rollover to epoch E+1), secret from epoch E is still rejected!
        assert!(filter.check_and_insert(&secret).is_err());
    }

    #[test]
    fn test_cross_epoch_rollover_replay_rejection() {
        let mut filter = ReplayFilter::new(8192, 7);
        let mut epoch_e_secrets = Vec::new();

        // Epoch E: insert 50 distinct packets
        for i in 0u32..50 {
            let mut secret = [0u8; 32];
            secret[0..4].copy_from_slice(&i.to_be_bytes());
            assert!(filter.check_and_insert(&secret).is_ok());
            epoch_e_secrets.push(secret);
        }
        assert_eq!(filter.current_count(), 50);
        assert_eq!(filter.previous_count(), 0);
        assert_eq!(filter.count(), 50);

        // Epoch rollover: E -> E+1
        filter.rollover();
        assert_eq!(filter.current_count(), 0);
        assert_eq!(filter.previous_count(), 50);
        assert_eq!(filter.count(), 50);

        // Epoch E+1: All 50 packets from Epoch E must be rejected as cross-epoch replays
        for secret in &epoch_e_secrets {
            assert!(matches!(
                filter.check_and_insert(secret),
                Err(crate::SphinxError::ReplayDetected)
            ));
        }

        // Fresh packets arriving in Epoch E+1 should be accepted and added to current
        let new_secret = [0xeeu8; 32];
        assert!(filter.check_and_insert(&new_secret).is_ok());
        assert_eq!(filter.current_count(), 1);
        assert_eq!(filter.previous_count(), 50);
        assert_eq!(filter.count(), 51);
    }

    #[test]
    fn test_two_rollovers_cleanly_retires_tags_from_epoch_e() {
        let mut filter = ReplayFilter::new(8192, 7);
        let secret_e = [0x11u8; 32];
        let secret_e1 = [0x22u8; 32];

        // Epoch E: process secret_e
        assert!(filter.check_and_insert(&secret_e).is_ok());
        assert!(filter.check_and_insert(&secret_e).is_err());

        // First rollover: E -> E+1
        filter.rollover();
        // In E+1: secret_e is still rejected (retained in previous)
        assert!(matches!(
            filter.check_and_insert(&secret_e),
            Err(crate::SphinxError::ReplayDetected)
        ));

        // Process secret_e1 in Epoch E+1
        assert!(filter.check_and_insert(&secret_e1).is_ok());

        // Second rollover: E+1 -> E+2
        filter.rollover();
        // In E+2: secret_e1 is now in previous (rejected)
        assert!(matches!(
            filter.check_and_insert(&secret_e1),
            Err(crate::SphinxError::ReplayDetected)
        ));
        // secret_e from epoch E has been retired (no longer in current or previous)
        assert!(filter.check_and_insert(&secret_e).is_ok());
    }

    #[test]
    fn test_clear_wipes_all_filters() {
        let mut filter = ReplayFilter::new(1024, 5);
        let secret = [7u8; 32];

        filter.check_and_insert(&secret).unwrap();
        filter.rollover();
        assert!(filter.check_and_insert(&secret).is_err());

        // Explicit clear wipes both current and previous
        filter.clear();
        assert_eq!(filter.count(), 0);
        assert_eq!(filter.current_count(), 0);
        assert_eq!(filter.previous_count(), 0);
        assert!(filter.check_and_insert(&secret).is_ok());
    }

    #[test]
    fn test_might_contain_and_insert_api() {
        let mut filter = ReplayFilter::new(1024, 5);
        let secret = [33u8; 32];
        let tag = ReplayFilter::derive_tag(&secret);

        assert!(!filter.might_contain(&tag));
        assert!(!filter.insert(&tag)); // false means wasn't present
        assert!(filter.might_contain(&tag));
        assert!(filter.insert(&tag)); // true means was present (replay)

        filter.rollover();
        assert!(filter.might_contain(&tag));
        assert!(filter.insert(&tag)); // true (replay caught in previous)
    }

    #[test]
    fn tag_derivation_deterministic() {
        let secret = [99u8; 32];
        let tag1 = ReplayFilter::derive_tag(&secret);
        let tag2 = ReplayFilter::derive_tag(&secret);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn tag_derivation_different_secrets() {
        let tag1 = ReplayFilter::derive_tag(&[1u8; 32]);
        let tag2 = ReplayFilter::derive_tag(&[2u8; 32]);
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_saturation_check() {
        let mut filter = ReplayFilter::new(128, 3);
        assert!(!filter.is_saturated(0.05));
        for i in 0..200 {
            let secret = [i as u8; 32];
            let _ = filter.check_and_insert(&secret);
        }
        assert!(filter.is_saturated(0.05));
    }
}
