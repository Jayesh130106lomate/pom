use std::time::{Duration, Instant};

use prism_sphinx::constants::MAX_PAYLOAD_DATA;
use prism_sphinx::fragment::{Fragment, FragmentHeader, Fragmenter, ReassemblyConfig, ReassemblyPool};
use prism_sphinx::errors::SphinxError;

fn create_raw_fragment(
    message_id: [u8; 16],
    fragment_index: u32,
    total_fragments: u32,
    total_length: u32,
    data: Vec<u8>,
) -> Fragment {
    Fragment {
        header: FragmentHeader {
            message_id,
            fragment_index,
            total_fragments,
            data_length: data.len() as u32,
            total_length,
            reserved: [0u8; 8],
        },
        data,
    }
}

#[test]
fn test_pool_successful_roundtrip_multifragment() {
    let mut pool = ReassemblyPool::default();
    let original = vec![0x42u8; MAX_PAYLOAD_DATA * 3 + 777];
    let frags = Fragmenter::fragment(&original).expect("fragmentation should succeed");
    assert_eq!(frags.len(), 4);

    // Feed first 3 fragments out-of-order
    assert_eq!(pool.add_fragment(&frags[2]).unwrap(), None);
    assert_eq!(pool.add_fragment(&frags[0]).unwrap(), None);
    assert_eq!(pool.add_fragment(&frags[3]).unwrap(), None);
    assert_eq!(pool.active_count(), 1);
    assert!(pool.current_memory_bytes() > 0);

    // Final fragment completes assembly
    let assembled = pool.add_fragment(&frags[1]).unwrap().expect("should reassemble");
    assert_eq!(assembled, original);
    assert_eq!(pool.active_count(), 0);
    assert_eq!(pool.current_memory_bytes(), 0);
}

#[test]
fn test_pool_single_fragment_fast_path() {
    let mut pool = ReassemblyPool::default();
    let data = b"single small message".to_vec();
    let frag = create_raw_fragment([1u8; 16], 0, 1, data.len() as u32, data.clone());

    let assembled = pool.add_fragment(&frag).unwrap().expect("should return immediate result");
    assert_eq!(assembled, data);
    assert_eq!(pool.active_count(), 0);
    assert_eq!(pool.current_memory_bytes(), 0);
}

#[test]
fn test_adversarial_oversized_total_fragments_rejected_without_allocation() {
    let mut pool = ReassemblyPool::default();
    let malicious_frag = create_raw_fragment(
        [2u8; 16],
        0,
        1_000_000_000, // 10^9 fragments!
        u32::MAX,
        vec![0u8; 100],
    );

    let res = pool.add_fragment(&malicious_frag);
    assert!(res.is_err(), "Must reject oversized total_fragments");
    match res {
        Err(SphinxError::InvalidFragment(msg)) => {
            assert!(msg.contains("exceeds configured maximum"));
        }
        other => panic!("Unexpected result: {:?}", other),
    }

    assert_eq!(pool.active_count(), 0);
    assert_eq!(pool.current_memory_bytes(), 0);
}

#[test]
fn test_adversarial_zero_total_fragments_rejected() {
    let mut pool = ReassemblyPool::default();
    let malicious_frag = create_raw_fragment([3u8; 16], 0, 0, 0, vec![0u8; 10]);

    let res = pool.add_fragment(&malicious_frag);
    assert!(res.is_err(), "Must reject total_fragments == 0");
    assert_eq!(pool.active_count(), 0);
    assert_eq!(pool.current_memory_bytes(), 0);
}

#[test]
fn test_adversarial_out_of_bounds_fragment_index_rejected() {
    let mut pool = ReassemblyPool::default();
    // fragment_index = 5, total_fragments = 3
    let malicious_frag = create_raw_fragment([4u8; 16], 5, 3, 300, vec![0u8; 100]);

    let res = pool.add_fragment(&malicious_frag);
    assert!(res.is_err(), "Must reject index >= total_fragments");
    assert_eq!(pool.active_count(), 0);
    assert_eq!(pool.current_memory_bytes(), 0);
}

#[test]
fn test_adversarial_data_length_exceeds_max_payload() {
    let mut pool = ReassemblyPool::default();
    let bad_data = vec![0u8; MAX_PAYLOAD_DATA + 10];
    let malicious_frag = create_raw_fragment([5u8; 16], 0, 2, 60000, bad_data);

    let res = pool.add_fragment(&malicious_frag);
    assert!(res.is_err(), "Must reject data_length > MAX_PAYLOAD_DATA");
    assert_eq!(pool.active_count(), 0);
    assert_eq!(pool.current_memory_bytes(), 0);
}

#[test]
fn test_adversarial_buffer_length_mismatch_rejected() {
    let mut pool = ReassemblyPool::default();
    let mut frag = create_raw_fragment([6u8; 16], 0, 2, 200, vec![0u8; 100]);
    // Tamper header data_length to not match data.len()
    frag.header.data_length = 50;

    let res = pool.add_fragment(&frag);
    assert!(res.is_err(), "Must reject buffer length mismatch");
    assert_eq!(pool.active_count(), 0);
    assert_eq!(pool.current_memory_bytes(), 0);
}

#[test]
fn test_adversarial_fragment_flood_exceeding_max_concurrent() {
    let config = ReassemblyConfig {
        max_concurrent_reassemblies: 5,
        max_fragments_per_message: 10,
        max_total_memory_bytes: 1024 * 1024,
        reassembly_ttl: Duration::from_secs(60),
    };
    let mut pool = ReassemblyPool::new(config);

    // Insert 5 incomplete messages
    for i in 0..5u8 {
        let frag = create_raw_fragment([i; 16], 0, 3, 300, vec![0xAA; 100]);
        let res = pool.add_fragment(&frag).unwrap();
        assert_eq!(res, None);
    }
    assert_eq!(pool.active_count(), 5);

    // 6th message should be rejected due to max concurrent limit
    let overflow_frag = create_raw_fragment([99u8; 16], 0, 3, 300, vec![0xBB; 100]);
    let res = pool.add_fragment(&overflow_frag);
    assert!(res.is_err(), "Must reject flood exceeding max_concurrent_reassemblies");
    match res {
        Err(SphinxError::ReassemblyError(msg)) => {
            assert!(msg.contains("max concurrent reassemblies limit"));
        }
        other => panic!("Unexpected result: {:?}", other),
    }

    assert_eq!(pool.active_count(), 5);
}

#[test]
fn test_adversarial_memory_saturation_safely_shed() {
    // Config: allow 10 concurrent, but only 500 bytes total memory
    let config = ReassemblyConfig {
        max_concurrent_reassemblies: 10,
        max_fragments_per_message: 10,
        max_total_memory_bytes: 500,
        reassembly_ttl: Duration::from_secs(60),
    };
    let mut pool = ReassemblyPool::new(config);

    // Insert 4 messages with 100 bytes each = 400 bytes
    for i in 0..4u8 {
        let frag = create_raw_fragment([i; 16], 0, 2, 200, vec![0xAA; 100]);
        assert_eq!(pool.add_fragment(&frag).unwrap(), None);
    }
    assert_eq!(pool.current_memory_bytes(), 400);

    // 5th message tries to add 150 bytes -> 400 + 150 = 550 > 500 -> rejected!
    let overflow_frag = create_raw_fragment([99u8; 16], 0, 2, 300, vec![0xBB; 150]);
    let res = pool.add_fragment(&overflow_frag);
    assert!(res.is_err(), "Must reject fragment causing memory saturation");
    match res {
        Err(SphinxError::ReassemblyError(msg)) => {
            assert!(msg.contains("memory limit exceeded"));
        }
        other => panic!("Unexpected result: {:?}", other),
    }

    // Memory remained capped at 400
    assert_eq!(pool.current_memory_bytes(), 400);
}

#[test]
fn test_duplicate_fragment_resilience_no_memory_leak() {
    let mut pool = ReassemblyPool::default();
    let frag0 = create_raw_fragment([7u8; 16], 0, 2, 200, vec![0x11; 100]);
    let frag1 = create_raw_fragment([7u8; 16], 1, 2, 200, vec![0x22; 100]);

    // Send frag0 first
    assert_eq!(pool.add_fragment(&frag0).unwrap(), None);
    assert_eq!(pool.current_memory_bytes(), 100);

    // Send duplicate frag0 multiple times
    for _ in 0..5 {
        assert_eq!(pool.add_fragment(&frag0).unwrap(), None);
        assert_eq!(pool.current_memory_bytes(), 100, "Duplicate must not increase memory");
    }

    // Now send frag1 to complete
    let assembled = pool.add_fragment(&frag1).unwrap().expect("should reassemble");
    let mut expected = vec![0x11; 100];
    expected.extend_from_slice(&vec![0x22; 100]);
    assert_eq!(assembled, expected);
    assert_eq!(pool.current_memory_bytes(), 0, "Memory must be zeroed upon completion");
}

#[test]
fn test_mismatched_metadata_for_same_message_id_rejected() {
    let mut pool = ReassemblyPool::default();
    let frag0 = create_raw_fragment([8u8; 16], 0, 3, 300, vec![0x11; 100]);
    assert_eq!(pool.add_fragment(&frag0).unwrap(), None);

    // Attacker sends fragment with same message_id but total_fragments = 5
    let bad_frag1 = create_raw_fragment([8u8; 16], 1, 5, 300, vec![0x22; 100]);
    assert!(pool.add_fragment(&bad_frag1).is_err(), "Must reject total_fragments mismatch");

    // Attacker sends fragment with same message_id but total_length = 999
    let bad_frag2 = create_raw_fragment([8u8; 16], 1, 3, 999, vec![0x22; 100]);
    assert!(pool.add_fragment(&bad_frag2).is_err(), "Must reject total_length mismatch");
}

#[test]
fn test_ttl_expiration_and_memory_reclaim() {
    let config = ReassemblyConfig {
        max_concurrent_reassemblies: 10,
        max_fragments_per_message: 10,
        max_total_memory_bytes: 1024 * 1024,
        reassembly_ttl: Duration::from_millis(50),
    };
    let mut pool = ReassemblyPool::new(config);
    let start = Instant::now();

    // Add incomplete fragment at t = 0
    let frag = create_raw_fragment([9u8; 16], 0, 2, 200, vec![0xAA; 100]);
    assert_eq!(pool.add_fragment_at(&frag, start).unwrap(), None);
    assert_eq!(pool.active_count(), 1);
    assert_eq!(pool.current_memory_bytes(), 100);

    // Advance time before TTL
    let t_pre = start + Duration::from_millis(20);
    assert_eq!(pool.prune_expired_at(t_pre), 0);
    assert_eq!(pool.active_count(), 1);
    assert_eq!(pool.current_memory_bytes(), 100);

    // Advance time past TTL (t = start + 60ms)
    let t_post = start + Duration::from_millis(60);
    let pruned = pool.prune_expired_at(t_post);
    assert_eq!(pruned, 1, "Must prune expired reassembly");
    assert_eq!(pool.active_count(), 0);
    assert_eq!(pool.current_memory_bytes(), 0, "Memory must be fully reclaimed on expiration");
}
