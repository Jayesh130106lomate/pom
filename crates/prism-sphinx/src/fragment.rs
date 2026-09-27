//! Message fragmentation and reassembly.
//!
//! Messages larger than MAX_PAYLOAD_DATA are split into fixed-size fragments,
//! each sent in a separate Sphinx packet. The recipient reassembles them.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::constants::*;
use crate::errors::SphinxError;

/// Fragment header prepended to each fragment's payload.
///
/// Layout (40 bytes):
///   [0..16]   Message ID (random, shared across all fragments of one message)
///   [16..20]  Fragment index (0-based, big-endian u32)
///   [20..24]  Total fragments (big-endian u32)
///   [24..28]  Fragment data length (big-endian u32, actual data in this fragment)
///   [28..32]  Total message length (big-endian u32)
///   [32..40]  Reserved / checksum
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentHeader {
    /// Unique message identifier (random 16 bytes).
    pub message_id: [u8; 16],
    /// Index of this fragment (0-based).
    pub fragment_index: u32,
    /// Total number of fragments.
    pub total_fragments: u32,
    /// Length of actual data in this fragment (may be less than MAX_PAYLOAD_DATA for the last fragment).
    pub data_length: u32,
    /// Total original message length.
    pub total_length: u32,
    /// Reserved bytes (for future use, e.g., checksum).
    pub reserved: [u8; 8],
}

impl FragmentHeader {
    pub fn to_bytes(&self) -> [u8; FRAGMENT_HEADER_SIZE] {
        let mut buf = [0u8; FRAGMENT_HEADER_SIZE];
        buf[0..16].copy_from_slice(&self.message_id);
        buf[16..20].copy_from_slice(&self.fragment_index.to_be_bytes());
        buf[20..24].copy_from_slice(&self.total_fragments.to_be_bytes());
        buf[24..28].copy_from_slice(&self.data_length.to_be_bytes());
        buf[28..32].copy_from_slice(&self.total_length.to_be_bytes());
        buf[32..40].copy_from_slice(&self.reserved);
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, SphinxError> {
        if buf.len() < FRAGMENT_HEADER_SIZE {
            return Err(SphinxError::InvalidFragment(format!(
                "fragment header too short: {} < {}",
                buf.len(),
                FRAGMENT_HEADER_SIZE
            )));
        }

        let mut message_id = [0u8; 16];
        message_id.copy_from_slice(&buf[0..16]);

        let fragment_index = u32::from_be_bytes(buf[16..20].try_into().unwrap());
        let total_fragments = u32::from_be_bytes(buf[20..24].try_into().unwrap());
        let data_length = u32::from_be_bytes(buf[24..28].try_into().unwrap());
        let total_length = u32::from_be_bytes(buf[28..32].try_into().unwrap());

        let mut reserved = [0u8; 8];
        reserved.copy_from_slice(&buf[32..40]);

        Ok(FragmentHeader {
            message_id,
            fragment_index,
            total_fragments,
            data_length,
            total_length,
            reserved,
        })
    }
}

/// A single fragment containing header + data.
#[derive(Debug, Clone)]
pub struct Fragment {
    pub header: FragmentHeader,
    pub data: Vec<u8>,
}

impl Fragment {
    /// Serialize to bytes (header + data, padded to MAX_PAYLOAD_DATA + FRAGMENT_HEADER_SIZE).
    pub fn to_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(PAYLOAD_SIZE);
        payload.extend_from_slice(&self.header.to_bytes());
        payload.extend_from_slice(&self.data);
        // Pad to PAYLOAD_SIZE minus room for encryption overhead
        // The actual padding to full payload size happens during Sphinx packet construction
        payload
    }

    /// Deserialize from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, SphinxError> {
        let header = FragmentHeader::from_bytes(payload)?;

        if header.total_fragments == 0 {
            return Err(SphinxError::InvalidFragment(
                "total_fragments cannot be 0".into(),
            ));
        }
        if header.fragment_index >= header.total_fragments {
            return Err(SphinxError::InvalidFragment(format!(
                "fragment_index {} >= total_fragments {}",
                header.fragment_index, header.total_fragments
            )));
        }
        if header.data_length as usize > MAX_PAYLOAD_DATA {
            return Err(SphinxError::InvalidFragment(format!(
                "fragment data_length {} exceeds MAX_PAYLOAD_DATA {}",
                header.data_length, MAX_PAYLOAD_DATA
            )));
        }

        let data_start = FRAGMENT_HEADER_SIZE;
        let data_end = data_start + header.data_length as usize;

        if data_end > payload.len() {
            return Err(SphinxError::InvalidFragment(format!(
                "fragment data extends beyond payload: {} > {}",
                data_end,
                payload.len()
            )));
        }

        Ok(Fragment {
            header,
            data: payload[data_start..data_end].to_vec(),
        })
    }
}

/// Fragmenter splits a message into Sphinx-sized fragments.
pub struct Fragmenter;

impl Fragmenter {
    /// Fragment a message into chunks that fit in Sphinx payloads.
    /// Each fragment includes a FragmentHeader.
    pub fn fragment(message: &[u8]) -> Result<Vec<Fragment>, SphinxError> {
        if message.is_empty() {
            return Err(SphinxError::FragmentationError(
                "cannot fragment empty message".into(),
            ));
        }

        let max_data = MAX_PAYLOAD_DATA;
        let total_fragments = (message.len() + max_data - 1) / max_data;

        if total_fragments > u32::MAX as usize {
            return Err(SphinxError::FragmentationError(
                "message too large to fragment".into(),
            ));
        }

        // Generate a random message ID
        let mut message_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut message_id);

        let mut fragments = Vec::with_capacity(total_fragments);

        for i in 0..total_fragments {
            let start = i * max_data;
            let end = std::cmp::min(start + max_data, message.len());
            let chunk = &message[start..end];

            let header = FragmentHeader {
                message_id,
                fragment_index: i as u32,
                total_fragments: total_fragments as u32,
                data_length: chunk.len() as u32,
                total_length: message.len() as u32,
                reserved: [0u8; 8],
            };

            fragments.push(Fragment {
                header,
                data: chunk.to_vec(),
            });
        }

        Ok(fragments)
    }
}

/// Reassembler collects fragments and reconstructs the original message.
pub struct Reassembler {
    /// Message ID we're collecting for.
    message_id: [u8; 16],
    /// Total fragments expected.
    total_fragments: u32,
    /// Total message length.
    total_length: u32,
    /// Collected fragments indexed by fragment_index.
    fragments: Vec<Option<Vec<u8>>>,
    /// Number of fragments received.
    received: usize,
}

impl Reassembler {
    /// Try to create a new reassembler from the first fragment received.
    pub fn try_new(first_fragment: &Fragment) -> Result<Self, SphinxError> {
        let total = first_fragment.header.total_fragments as usize;
        if total == 0 {
            return Err(SphinxError::InvalidFragment("total_fragments cannot be 0".into()));
        }
        let idx = first_fragment.header.fragment_index as usize;
        if idx >= total {
            return Err(SphinxError::InvalidFragment(format!(
                "fragment_index {} out of bounds for total_fragments {}",
                idx, total
            )));
        }

        let mut fragments = vec![None; total];
        fragments[idx] = Some(first_fragment.data.clone());

        Ok(Reassembler {
            message_id: first_fragment.header.message_id,
            total_fragments: first_fragment.header.total_fragments,
            total_length: first_fragment.header.total_length,
            fragments,
            received: 1,
        })
    }

    /// Create a new reassembler from the first fragment received.
    pub fn new(first_fragment: &Fragment) -> Self {
        Self::try_new(first_fragment).expect("invalid first fragment for Reassembler::new")
    }

    /// Add a fragment. Returns Ok(true) if all fragments are now received.
    pub fn add_fragment(&mut self, fragment: &Fragment) -> Result<bool, SphinxError> {
        if fragment.header.message_id != self.message_id {
            return Err(SphinxError::ReassemblyError(
                "fragment message_id mismatch".into(),
            ));
        }

        let idx = fragment.header.fragment_index as usize;
        if idx >= self.fragments.len() {
            return Err(SphinxError::ReassemblyError(format!(
                "fragment index {} out of range (total: {})",
                idx, self.total_fragments
            )));
        }

        if self.fragments[idx].is_none() {
            self.fragments[idx] = Some(fragment.data.clone());
            self.received += 1;
        }

        Ok(self.is_complete())
    }

    /// Check if all fragments have been received.
    pub fn is_complete(&self) -> bool {
        self.received == self.total_fragments as usize
    }

    /// How many fragments are still missing.
    pub fn missing_count(&self) -> usize {
        self.total_fragments as usize - self.received
    }

    /// Reassemble the complete message.
    pub fn reassemble(&self) -> Result<Vec<u8>, SphinxError> {
        if !self.is_complete() {
            return Err(SphinxError::ReassemblyIncomplete {
                have: self.received,
                total: self.total_fragments as usize,
            });
        }

        let mut message = Vec::with_capacity(self.total_length as usize);
        for (i, frag) in self.fragments.iter().enumerate() {
            match frag {
                Some(data) => message.extend_from_slice(data),
                None => {
                    return Err(SphinxError::ReassemblyError(format!(
                        "missing fragment {}",
                        i
                    )));
                }
            }
        }

        // Verify total length
        if message.len() != self.total_length as usize {
            return Err(SphinxError::ReassemblyError(format!(
                "reassembled length {} != expected {}",
                message.len(),
                self.total_length
            )));
        }

        Ok(message)
    }
}

/// Configuration for memory-safe message fragment reassembly.
#[derive(Debug, Clone)]
pub struct ReassemblyConfig {
    /// Maximum concurrent messages undergoing reassembly (default: 256).
    pub max_concurrent_reassemblies: usize,
    /// Maximum allowed fragments per message (default: 256 fragments ≈ 8.1 MB).
    pub max_fragments_per_message: u32,
    /// Maximum memory in bytes across all buffered fragment data (default: 32 MB).
    pub max_total_memory_bytes: usize,
    /// Time-to-live expiration for incomplete reassembly sets (default: 60s).
    pub reassembly_ttl: Duration,
}

impl Default for ReassemblyConfig {
    fn default() -> Self {
        Self {
            max_concurrent_reassemblies: 256,
            max_fragments_per_message: 256,
            max_total_memory_bytes: 32 * 1024 * 1024,
            reassembly_ttl: Duration::from_secs(60),
        }
    }
}

/// Internal state for an in-flight fragmented message.
#[derive(Debug)]
struct ReassemblyEntry {
    created_at: Instant,
    last_updated: Instant,
    total_fragments: u32,
    total_length: u32,
    fragments: Vec<Option<Vec<u8>>>,
    received_count: usize,
    buffered_bytes: usize,
}

/// Memory-safe pool for tracking and reassembling fragmented messages.
///
/// Defends against:
/// - Malicious oversized fragment headers (total_fragments up to 2^32-1)
/// - Memory exhaustion from abandoned or incomplete fragment floods
/// - Table exhaustion from high-concurrency reassembly spam
/// - Reassembly buffer memory saturation
#[derive(Debug)]
pub struct ReassemblyPool {
    config: ReassemblyConfig,
    entries: HashMap<[u8; 16], ReassemblyEntry>,
    current_memory_bytes: AtomicUsize,
}

impl ReassemblyPool {
    /// Create a new reassembly pool with the given configuration.
    pub fn new(config: ReassemblyConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            current_memory_bytes: AtomicUsize::new(0),
        }
    }

    /// Access the active configuration.
    pub fn config(&self) -> &ReassemblyConfig {
        &self.config
    }

    /// Number of distinct messages currently undergoing reassembly.
    pub fn active_count(&self) -> usize {
        self.entries.len()
    }

    /// Total memory allocated to buffered fragments in bytes.
    pub fn current_memory_bytes(&self) -> usize {
        self.current_memory_bytes.load(Ordering::Relaxed)
    }

    /// Prune any incomplete reassemblies that have exceeded their TTL.
    /// Returns the number of pruned messages.
    pub fn prune_expired(&mut self) -> usize {
        self.prune_expired_at(Instant::now())
    }

    /// Prune expired entries relative to a specific time (useful for deterministic testing).
    pub fn prune_expired_at(&mut self, now: Instant) -> usize {
        let ttl = self.config.reassembly_ttl;
        let mut expired_keys = Vec::new();

        for (&key, entry) in &self.entries {
            if now.saturating_duration_since(entry.last_updated) >= ttl
                || now.saturating_duration_since(entry.created_at) >= ttl
            {
                expired_keys.push(key);
            }
        }

        let pruned_count = expired_keys.len();
        for key in expired_keys {
            if let Some(entry) = self.entries.remove(&key) {
                self.current_memory_bytes.fetch_sub(entry.buffered_bytes, Ordering::Relaxed);
            }
        }

        pruned_count
    }

    /// Validate fragment metadata without allocating any reassembly state.
    pub fn validate_fragment(&self, fragment: &Fragment) -> Result<(), SphinxError> {
        let header = &fragment.header;

        if header.total_fragments == 0 {
            return Err(SphinxError::InvalidFragment(
                "fragment total_fragments cannot be 0".into(),
            ));
        }

        if header.total_fragments > self.config.max_fragments_per_message {
            return Err(SphinxError::InvalidFragment(format!(
                "fragment total_fragments {} exceeds configured maximum {}",
                header.total_fragments, self.config.max_fragments_per_message
            )));
        }

        if header.fragment_index >= header.total_fragments {
            return Err(SphinxError::InvalidFragment(format!(
                "fragment_index {} out of bounds for total_fragments {}",
                header.fragment_index, header.total_fragments
            )));
        }

        if header.data_length as usize > MAX_PAYLOAD_DATA {
            return Err(SphinxError::InvalidFragment(format!(
                "fragment data_length {} exceeds MAX_PAYLOAD_DATA {}",
                header.data_length, MAX_PAYLOAD_DATA
            )));
        }

        if fragment.data.len() != header.data_length as usize {
            return Err(SphinxError::InvalidFragment(format!(
                "fragment data length {} does not match header data_length {}",
                fragment.data.len(), header.data_length
            )));
        }

        if header.total_length as usize > (header.total_fragments as usize) * MAX_PAYLOAD_DATA {
            return Err(SphinxError::InvalidFragment(format!(
                "fragment total_length {} exceeds maximum possible {} for {} fragments",
                header.total_length,
                (header.total_fragments as usize) * MAX_PAYLOAD_DATA,
                header.total_fragments
            )));
        }

        const MAX_TOTAL_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
        if header.total_length as usize > MAX_TOTAL_MESSAGE_SIZE {
            return Err(SphinxError::InvalidFragment(format!(
                "fragment total_length {} exceeds maximum allowed message size {}",
                header.total_length, MAX_TOTAL_MESSAGE_SIZE
            )));
        }

        Ok(())
    }

    /// Process a fragment.
    ///
    /// - If the fragment is invalid or causes memory/concurrency exhaustion, returns `Err`.
    /// - If valid but the message is still incomplete, returns `Ok(None)`.
    /// - If the fragment completes the message, removes the message from the pool,
    ///   reclaims memory tracking, and returns `Ok(Some(reassembled_message))`.
    pub fn add_fragment(&mut self, fragment: &Fragment) -> Result<Option<Vec<u8>>, SphinxError> {
        self.add_fragment_at(fragment, Instant::now())
    }

    /// Process a fragment with a specific arrival timestamp (for deterministic testing).
    pub fn add_fragment_at(
        &mut self,
        fragment: &Fragment,
        now: Instant,
    ) -> Result<Option<Vec<u8>>, SphinxError> {
        // 1. Proactively prune expired entries
        self.prune_expired_at(now);

        // 2. Validate metadata strictly prior to any memory allocation
        self.validate_fragment(fragment)?;

        let msg_id = fragment.header.message_id;
        let idx = fragment.header.fragment_index as usize;
        let frag_len = fragment.data.len();

        // 3. Admission control & duplicate check
        if let Some(entry) = self.entries.get_mut(&msg_id) {
            // Check consistency with earlier fragments
            if entry.total_fragments != fragment.header.total_fragments {
                return Err(SphinxError::ReassemblyError(format!(
                    "total_fragments mismatch for message_id: expected {}, got {}",
                    entry.total_fragments, fragment.header.total_fragments
                )));
            }

            if entry.total_length != fragment.header.total_length {
                return Err(SphinxError::ReassemblyError(format!(
                    "total_length mismatch for message_id: expected {}, got {}",
                    entry.total_length, fragment.header.total_length
                )));
            }

            // Duplicate fragment check
            if entry.fragments[idx].is_some() {
                // Already stored; ignore duplicate
                return Ok(None);
            }

            // Check total memory budget
            let current_mem = self.current_memory_bytes.load(Ordering::Relaxed);
            if current_mem.saturating_add(frag_len) > self.config.max_total_memory_bytes {
                return Err(SphinxError::ReassemblyError(format!(
                    "reassembly pool memory limit exceeded: {} + {} > {}",
                    current_mem, frag_len, self.config.max_total_memory_bytes
                )));
            }

            entry.fragments[idx] = Some(fragment.data.clone());
            entry.received_count += 1;
            entry.buffered_bytes += frag_len;
            entry.last_updated = now;
            self.current_memory_bytes.fetch_add(frag_len, Ordering::Relaxed);

            if entry.received_count == entry.total_fragments as usize {
                // Message complete! Remove from pool and assemble
                let completed = self.entries.remove(&msg_id).unwrap();
                self.current_memory_bytes.fetch_sub(completed.buffered_bytes, Ordering::Relaxed);

                let mut message = Vec::with_capacity(completed.total_length as usize);
                for (i, opt) in completed.fragments.into_iter().enumerate() {
                    match opt {
                        Some(data) => message.extend_from_slice(&data),
                        None => {
                            return Err(SphinxError::ReassemblyError(format!(
                                "missing fragment {} upon completion",
                                i
                            )));
                        }
                    }
                }

                if message.len() != completed.total_length as usize {
                    return Err(SphinxError::ReassemblyError(format!(
                        "reassembled length {} != expected {}",
                        message.len(), completed.total_length
                    )));
                }

                return Ok(Some(message));
            }

            Ok(None)
        } else {
            // New message reassembly entry
            // If single-fragment message, fast-path completion without persisting in pool
            if fragment.header.total_fragments == 1 {
                if fragment.header.total_length as usize != frag_len {
                    return Err(SphinxError::ReassemblyError(format!(
                        "single fragment length {} != expected total_length {}",
                        frag_len, fragment.header.total_length
                    )));
                }
                return Ok(Some(fragment.data.clone()));
            }

            // Check concurrent message capacity
            if self.entries.len() >= self.config.max_concurrent_reassemblies {
                return Err(SphinxError::ReassemblyError(format!(
                    "max concurrent reassemblies limit ({}) reached",
                    self.config.max_concurrent_reassemblies
                )));
            }

            // Check memory capacity
            let current_mem = self.current_memory_bytes.load(Ordering::Relaxed);
            if current_mem.saturating_add(frag_len) > self.config.max_total_memory_bytes {
                return Err(SphinxError::ReassemblyError(format!(
                    "reassembly pool memory limit exceeded: {} + {} > {}",
                    current_mem, frag_len, self.config.max_total_memory_bytes
                )));
            }

            let mut fragments = vec![None; fragment.header.total_fragments as usize];
            fragments[idx] = Some(fragment.data.clone());

            let entry = ReassemblyEntry {
                created_at: now,
                last_updated: now,
                total_fragments: fragment.header.total_fragments,
                total_length: fragment.header.total_length,
                fragments,
                received_count: 1,
                buffered_bytes: frag_len,
            };

            self.entries.insert(msg_id, entry);
            self.current_memory_bytes.fetch_add(frag_len, Ordering::Relaxed);

            Ok(None)
        }
    }

    /// Clear all active reassemblies and reset memory metrics.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.current_memory_bytes.store(0, Ordering::Relaxed);
    }
}

impl Default for ReassemblyPool {
    fn default() -> Self {
        Self::new(ReassemblyConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_header_roundtrip() {
        let header = FragmentHeader {
            message_id: [42u8; 16],
            fragment_index: 3,
            total_fragments: 10,
            data_length: 1234,
            total_length: 50000,
            reserved: [0u8; 8],
        };

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), FRAGMENT_HEADER_SIZE);

        let recovered = FragmentHeader::from_bytes(&bytes).unwrap();
        assert_eq!(recovered, header);
    }

    #[test]
    fn fragment_small_message() {
        let message = b"hello world";
        let fragments = Fragmenter::fragment(message).unwrap();

        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].header.fragment_index, 0);
        assert_eq!(fragments[0].header.total_fragments, 1);
        assert_eq!(fragments[0].data, message.to_vec());
    }

    #[test]
    fn fragment_large_message() {
        // Create a message larger than MAX_PAYLOAD_DATA
        let message = vec![0xAB; MAX_PAYLOAD_DATA * 3 + 100];
        let fragments = Fragmenter::fragment(&message).unwrap();

        assert_eq!(fragments.len(), 4);

        for (i, frag) in fragments.iter().enumerate() {
            assert_eq!(frag.header.fragment_index, i as u32);
            assert_eq!(frag.header.total_fragments, 4);
            assert_eq!(frag.header.total_length, message.len() as u32);
        }

        // Last fragment should be smaller
        assert_eq!(fragments[3].data.len(), 100);
    }

    #[test]
    fn reassemble_single_fragment() {
        let message = b"simple message";
        let fragments = Fragmenter::fragment(message).unwrap();

        let reassembler = Reassembler::new(&fragments[0]);
        assert!(reassembler.is_complete());

        let result = reassembler.reassemble().unwrap();
        assert_eq!(result, message.to_vec());
    }

    #[test]
    fn reassemble_multiple_fragments() {
        let message = vec![0xCD; MAX_PAYLOAD_DATA * 2 + 500];
        let fragments = Fragmenter::fragment(&message).unwrap();
        assert_eq!(fragments.len(), 3);

        let mut reassembler = Reassembler::new(&fragments[0]);
        assert!(!reassembler.is_complete());

        // Add out of order
        reassembler.add_fragment(&fragments[2]).unwrap();
        assert!(!reassembler.is_complete());

        reassembler.add_fragment(&fragments[1]).unwrap();
        assert!(reassembler.is_complete());

        let result = reassembler.reassemble().unwrap();
        assert_eq!(result, message);
    }

    #[test]
    fn reassemble_incomplete() {
        let message = vec![0xEF; MAX_PAYLOAD_DATA * 2 + 100];
        let fragments = Fragmenter::fragment(&message).unwrap();

        let reassembler = Reassembler::new(&fragments[0]);
        assert!(reassembler.reassemble().is_err());
    }

    #[test]
    fn fragment_empty_message() {
        assert!(Fragmenter::fragment(b"").is_err());
    }

    #[test]
    fn duplicate_fragment_ignored() {
        let message = vec![0xAA; MAX_PAYLOAD_DATA + 100];
        let fragments = Fragmenter::fragment(&message).unwrap();

        let mut reassembler = Reassembler::new(&fragments[0]);
        // Add same fragment again — should not increase count
        reassembler.add_fragment(&fragments[0]).unwrap();
        assert_eq!(reassembler.missing_count(), 1);

        reassembler.add_fragment(&fragments[1]).unwrap();
        assert!(reassembler.is_complete());
    }
}
