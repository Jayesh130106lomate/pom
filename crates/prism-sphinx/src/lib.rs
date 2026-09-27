//! # prism-sphinx
//!
//! Implementation of the Sphinx packet format for the PRISM privacy network.
//!
//! Sphinx provides:
//! - Bitwise unlinkability between hops (input and output packets are indistinguishable)
//! - Path-length hiding (all headers are the same size regardless of remaining hops)
//! - Per-hop MAC verification (tagging attack defense)
//! - Replay detection via packet tags
//! - Single-Use Reply Blocks (SURBs) for anonymous replies
//!
//! Reference: Danezis & Goldberg, "Sphinx: A Compact and Provably Secure Mix Format," IEEE S&P 2009.

pub mod constants;
pub mod errors;
pub mod fragment;
pub mod header;
pub mod packet;
pub mod payload;
pub mod replay;
pub mod routing;
pub mod pq_hybrid;
pub mod surb;

pub use constants::*;
pub use errors::SphinxError;
pub use packet::{SphinxPacket, ProcessedPacket};
pub use pq_hybrid::{PqSphinxPacket, PqRouteHop, PqProcessedPacket, create_pq_sphinx_packet, process_pq_sphinx_packet};
pub use routing::RoutingInfo;
pub use surb::Surb;
pub use fragment::{Fragment, FragmentHeader, Fragmenter, Reassembler, ReassemblyConfig, ReassemblyPool};
pub use replay::{BloomFilter, ReplayFilter};
