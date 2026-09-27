//! Constants for the Sphinx packet format.
//!
//! All packets in PRISM are fixed-size to prevent traffic analysis.

/// Total packet size in bytes (32 KB).
pub const PACKET_SIZE: usize = 32_768;

/// Header size in bytes.
pub const HEADER_SIZE: usize = 1_024;

/// Payload size in bytes (PACKET_SIZE - HEADER_SIZE).
pub const PAYLOAD_SIZE: usize = PACKET_SIZE - HEADER_SIZE;

/// Maximum number of hops in a route.
pub const MAX_HOPS: usize = 5;

/// Size of each per-hop routing block in the header (bytes).
/// Contains: serialized routing data (24 bytes) + next hop MAC tag (32 bytes) = 56 bytes total.
pub const ROUTING_BLOCK_SIZE: usize = 56;

/// Size of the ephemeral public key in the header (X25519 = 32 bytes).
/// For the research prototype, we use X25519 only (not hybrid PQ) to keep
/// the implementation focused. Hybrid PQ is a straightforward extension.
pub const EPHEMERAL_KEY_SIZE: usize = 32;

/// Size of a MAC tag (HMAC-SHA-256 = 32 bytes).
pub const MAC_SIZE: usize = 32;

/// Version field size.
pub const VERSION_SIZE: usize = 1;

/// Epoch ID field size.
pub const EPOCH_ID_SIZE: usize = 4;

/// Total routing info size in header.
pub const ROUTING_INFO_SIZE: usize = MAX_HOPS * ROUTING_BLOCK_SIZE;

/// Header breakdown:
/// version (1) + epoch_id (4) + ephemeral_pk (32) + routing_info (280) + padding
/// Total must be HEADER_SIZE (1024).
pub const HEADER_PADDING_SIZE: usize =
    HEADER_SIZE - VERSION_SIZE - EPOCH_ID_SIZE - EPHEMERAL_KEY_SIZE - ROUTING_INFO_SIZE - MAC_SIZE;

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// Poly1305 authentication tag size in bytes.
pub const PAYLOAD_TAG_SIZE: usize = 16;

/// Plaintext size before AEAD encryption (PAYLOAD_SIZE - PAYLOAD_TAG_SIZE = 31,728).
pub const PAYLOAD_PLAINTEXT_SIZE: usize = PAYLOAD_SIZE - PAYLOAD_TAG_SIZE;

/// Fragment header size within the payload.
pub const FRAGMENT_HEADER_SIZE: usize = 40;

/// Maximum payload data per packet (accounting for AEAD tag, padding length, and fragment header).
pub const MAX_PAYLOAD_DATA: usize = PAYLOAD_PLAINTEXT_SIZE - 4 - FRAGMENT_HEADER_SIZE;

/// SURB size in bytes.
pub const SURB_SIZE: usize = VERSION_SIZE + EPOCH_ID_SIZE + EPHEMERAL_KEY_SIZE
    + ROUTING_INFO_SIZE + MAC_SIZE + 32; // 32 bytes for the first-hop symmetric key

/// Bloom filter size for replay detection (bytes).
pub const BLOOM_FILTER_SIZE: usize = 1 << 20; // 1 MB

/// Number of hash functions for Bloom filter.
pub const BLOOM_HASH_COUNT: usize = 7;
