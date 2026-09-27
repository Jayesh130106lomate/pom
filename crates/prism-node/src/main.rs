//! PRISM relay node daemon.
//!
//! Runs a mix relay that processes and forwards Sphinx packets with
//! Poisson mixing delays.

mod config;
mod relay;
mod state;

use clap::Parser;
use tokio::sync::mpsc;
use tracing::info;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use config::NodeConfig;
use prism_transport::{TransportConfig, TransportServer};
use relay::RelayProcessor;

/// PRISM relay node daemon.
#[derive(Parser, Debug)]
#[command(name = "prism-node", about = "PRISM mix relay node")]
struct Args {
    /// Listen address (IP:port).
    #[arg(short, long, default_value = "0.0.0.0:9001")]
    listen: String,

    /// Layer assignment (1, 2, 3, ...).
    #[arg(short = 'L', long, default_value = "1")]
    layer: u8,

    /// Mixing rate parameter μ (mean delay = 1/μ seconds).
    #[arg(short, long, default_value = "2.0")]
    mix_rate: f64,

    /// Minimum pool size.
    #[arg(short, long, default_value = "5")]
    pool_size: usize,

    /// Optional private key as 64-char hex string, or integer seed (e.g., "1", "2", "3").
    #[arg(short, long)]
    key: Option<String>,

    /// Maximum ingress packet rate limit in packets/sec (0 for unthrottled benchmark mode).
    #[arg(long, default_value = "10000")]
    max_rate: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    info!("Starting PRISM relay node");

    // Load or generate relay master seed, then derive distinct domain-separated keys
    let master_seed = if let Some(ref k) = args.key {
        if k.len() == 64 {
            let bytes = hex::decode(k).map_err(|e| format!("Invalid hex key: {}", e))?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        } else if let Ok(seed) = k.parse::<u64>() {
            let mut arr = [0u8; 32];
            let seed_val = seed.wrapping_mul(8).wrapping_add(64);
            arr[0..8].copy_from_slice(&seed_val.to_le_bytes());
            arr[8] = (seed & 0xFF) as u8;
            arr
        } else {
            return Err("Key must be 64 hex characters or an integer seed like 1, 2, 3".into());
        }
    } else {
        let mut arr = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut arr);
        arr
    };

    // Derive cryptographically domain-separated keys from master seed
    let sphinx_key_bytes = prism_crypto::kdf::hkdf_sha256(
        &master_seed,
        b"prism-key-separation",
        b"sphinx-x25519-v1",
        32,
    );
    let mut sphinx_key = [0u8; 32];
    sphinx_key.copy_from_slice(&sphinx_key_bytes);

    let tls_seed_bytes = prism_crypto::kdf::hkdf_sha256(
        &master_seed,
        b"prism-key-separation",
        b"tls-ed25519-v1",
        32,
    );
    let mut tls_seed = [0u8; 32];
    tls_seed.copy_from_slice(&tls_seed_bytes);

    let relay_secret = X25519Secret::from(sphinx_key);
    let identity_seed = Some(tls_seed);
    let relay_public = X25519Public::from(&relay_secret);

    let listen_addr: std::net::SocketAddr = args.listen.parse()?;

    let max_mix_rate = match args.layer {
        1 => Some(2500.0),
        2 => Some(1500.0),
        _ => Some(2500.0),
    };

    let config = NodeConfig {
        listen_addr,
        layer: args.layer,
        mix_rate: args.mix_rate,
        min_pool_size: args.pool_size,
        epoch_id: 1,
        max_packet_rate: 3000,
        key_path: "relay_keys.json".into(),
        adaptive_mixing: true,
        max_mix_rate,
        target_anonymity_set: Some(args.pool_size.max(10)),
        batch_size: Some(64),
        max_pool_capacity: Some(512),
    };

    // Create packet channel with bounded capacity (512 packets = 16 MiB)
    let (packet_tx, packet_rx) = mpsc::channel(512);


    // Start transport server with cryptographically bound relay identity
    let transport_config = TransportConfig {
        bind_addr: config.listen_addr,
        packet_size: prism_sphinx::PACKET_SIZE,
        max_connections: 512,
        max_connections_per_ip: 256,
        rate_limit_per_ip_pps: (args.max_rate as f64).max(10_000.0),
        global_rate_limit_pps: (args.max_rate as f64 * 2.0).max(20_000.0),
        burst_factor: 10.0,
    };
    let server = TransportServer::new_with_identity(transport_config, identity_seed.as_ref())?;
    let local_addr = server.local_addr()?;
    let identity_key = server.public_identity();
    let server_metrics = server.metrics();
    info!("Listening on {}", local_addr);

    println!("╔════════════════════════════════════════════════════════════════════════╗");
    println!("║ PRISM Mixnet Relay Node Started                                       ║");
    println!("╠════════════════════════════════════════════════════════════════════════╣");
    println!("║ Listen Address : {:<53} ║", local_addr);
    println!("║ Layer          : {:<53} ║", args.layer);
    println!("║ Mix Rate (μ)   : {:<53} ║", format!("{:.1} (mean delay {:.0}ms)", args.mix_rate, 1000.0 / args.mix_rate));
    println!("║ Min Pool Size  : {:<53} ║", args.pool_size);
    println!("║ Public Key     : {:<53} ║", hex::encode(relay_public.as_bytes()));
    println!("║ Ed25519 Ident  : {:<53} ║", hex::encode(identity_key));
    println!("╚════════════════════════════════════════════════════════════════════════╝");

    // Start relay processor
    let processor = RelayProcessor::new(config, relay_secret.to_bytes())?;
    let state = processor.state();
    let mix_pool = processor.mix_pool();
    let replay_filter = processor.replay_filter();

    // Run transport and relay in parallel
    let transport_handle = tokio::spawn(async move {
        if let Err(e) = server.run(packet_tx).await {
            tracing::error!("Transport server error: {}", e);
        }
    });

    let relay_handle = tokio::spawn(async move {
        processor.run(packet_rx).await;
    });

    // Periodic status reporting and metric synchronization
    let status_state = state.clone();
    let status_layer = args.layer;
    let status_mix_pool = mix_pool.clone();
    let status_replay_filter = replay_filter.clone();
    let status_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            interval.tick().await;
            status_state.connections_rejected.store(
                server_metrics.connections_rejected.load(std::sync::atomic::Ordering::Relaxed),
                std::sync::atomic::Ordering::Relaxed,
            );
            status_state.packets_dropped_rate_limit.store(
                server_metrics.packets_dropped_rate_limit.load(std::sync::atomic::Ordering::Relaxed),
                std::sync::atomic::Ordering::Relaxed,
            );
            status_state.packets_dropped_backpressure.store(
                server_metrics.packets_dropped_backpressure.load(std::sync::atomic::Ordering::Relaxed),
                std::sync::atomic::Ordering::Relaxed,
            );
            status_state.active_connections.store(
                server_metrics.active_connections.load(std::sync::atomic::Ordering::Relaxed),
                std::sync::atomic::Ordering::Relaxed,
            );

            let (pool_depth, pool_cap) = {
                let pool = status_mix_pool.lock().await;
                (pool.len(), pool.max_capacity())
            };
            let (rf_count, rf_fpr) = {
                let rf = status_replay_filter.lock().await;
                (rf.count(), rf.estimated_fpr())
            };
            let prev_high = status_state.mix_pool_high_water.load(std::sync::atomic::Ordering::Relaxed);
            if pool_depth > prev_high {
                status_state.mix_pool_high_water.store(pool_depth, std::sync::atomic::Ordering::Relaxed);
            }
            status_state.mix_pool_depth.store(pool_depth, std::sync::atomic::Ordering::Relaxed);
            status_state.replay_filter_count.store(rf_count, std::sync::atomic::Ordering::Relaxed);
            status_state.replay_filter_fpr_ppm.store((rf_fpr * 1_000_000.0) as u64, std::sync::atomic::Ordering::Relaxed);

            info!("Status: {}", status_state.report());

            let status_json = serde_json::json!({
                "layer": status_layer,
                "received": status_state.packets_received.load(std::sync::atomic::Ordering::Relaxed),
                "forwarded": status_state.packets_forwarded.load(std::sync::atomic::Ordering::Relaxed),
                "delivered": status_state.packets_delivered.load(std::sync::atomic::Ordering::Relaxed),
                "dropped": status_state.packets_dropped.load(std::sync::atomic::Ordering::Relaxed),
                "replays": status_state.replays_detected.load(std::sync::atomic::Ordering::Relaxed),
                "mac_failures": status_state.mac_failures.load(std::sync::atomic::Ordering::Relaxed),
                "rate_limit_drops": status_state.packets_dropped_rate_limit.load(std::sync::atomic::Ordering::Relaxed),
                "backpressure_drops": status_state.packets_dropped_backpressure.load(std::sync::atomic::Ordering::Relaxed),
                "pool_overflows": status_state.pool_overflow_drops.load(std::sync::atomic::Ordering::Relaxed),
                "conns_rejected": status_state.connections_rejected.load(std::sync::atomic::Ordering::Relaxed),
                "active_conns": status_state.active_connections.load(std::sync::atomic::Ordering::Relaxed),
                "mix_pool_depth": pool_depth,
                "mix_pool_capacity": pool_cap,
                "mix_pool_high_water": status_state.mix_pool_high_water.load(std::sync::atomic::Ordering::Relaxed),
                "replay_filter_count": rf_count,
                "replay_filter_fpr": rf_fpr,
            });
            let _ = std::fs::write("/tmp/prism_status.json", status_json.to_string());
        }
    });

    tokio::select! {
        _ = transport_handle => {}
        _ = relay_handle => {}
        _ = tokio::signal::ctrl_c() => {
            info!("Shutting down...");
        }
    }

    status_handle.abort();

    Ok(())
}
