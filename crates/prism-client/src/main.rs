//! PRISM client CLI.
//!
//! Provides commands for generating identity, sending messages through
//! the mix network, and managing cover traffic.

mod circuit;

use clap::{Parser, Subcommand};
use tracing::info;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use circuit::Circuit;
use prism_sphinx::routing::{PacketFlag, RouteHop, RoutingInfo};
use prism_transport::{TransportClient, TransportConfig};

/// PRISM privacy network client.
#[derive(Parser, Debug)]
#[command(name = "prism-client", about = "PRISM privacy network client")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a new client identity.
    GenerateIdentity,

    /// Send a message through the mix network.
    Send {
        /// Message to send.
        #[arg(short, long)]
        message: String,

        /// Relay addresses (comma-separated, e.g., "127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003").
        #[arg(short, long)]
        relays: String,

        /// Relay public keys (comma-separated 64-char hex strings matching each relay in the route).
        #[arg(short, long)]
        keys: Option<String>,

        /// Relay seeds (comma-separated integers matching each relay started with --key <seed>, e.g., "1,2,3").
        #[arg(short, long)]
        seeds: Option<String>,
    },

    /// Show client status and configuration.
    Status,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    match args.command {
        Command::GenerateIdentity => {
            let secret = X25519Secret::random_from_rng(rand::thread_rng());
            let public = X25519Public::from(&secret);

            println!("PRISM Client Identity Generated");
            println!("Public key: {}", hex::encode(public.as_bytes()));
            println!("Secret key: {} (KEEP SECRET)", hex::encode(secret.to_bytes()));
        }

        Command::Send {
            message,
            relays,
            keys,
            seeds,
        } => {
            info!("Preparing to send message ({} bytes)", message.len());

            // Parse relay addresses
            let relay_addrs: Vec<std::net::SocketAddr> = relays
                .split(',')
                .map(|s| s.trim().parse())
                .collect::<Result<_, _>>()?;

            if relay_addrs.is_empty() {
                eprintln!("Error: at least one relay address required");
                return Ok(());
            }

            // Derive or parse relay public keys and cryptographic identity keys
            let (pks, identity_pks): (Vec<[u8; 32]>, Vec<Option<[u8; 32]>>) = if let Some(ref k_str) = keys {
                let parts: Vec<&str> = k_str.split(',').map(|s| s.trim()).collect();
                if parts.len() != relay_addrs.len() {
                    eprintln!("Error: Number of keys ({}) must match number of relays ({})", parts.len(), relay_addrs.len());
                    return Ok(());
                }
                let p = parts.iter().map(|hex_key| {
                    let b = hex::decode(hex_key).expect("Invalid hex key");
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }).collect();
                (p, vec![None; relay_addrs.len()])
            } else if let Some(ref s_str) = seeds {
                let parts: Vec<&str> = s_str.split(',').map(|s| s.trim()).collect();
                if parts.len() != relay_addrs.len() {
                    eprintln!("Error: Number of seeds ({}) must match number of relays ({})", parts.len(), relay_addrs.len());
                    return Ok(());
                }
                let mut p = Vec::new();
                let mut ids = Vec::new();
                for s in parts {
                    let seed: u64 = s.parse().expect("Invalid seed integer");
                    let mut arr = [0u8; 32];
                    let seed_val = seed * 8 + 64;
                    arr[0..8].copy_from_slice(&seed_val.to_le_bytes());
                    arr[8] = (seed & 0xFF) as u8;
                    let secret = X25519Secret::from(arr);
                    p.push(*X25519Public::from(&secret).as_bytes());

                    let dalek_sk = ed25519_dalek::SigningKey::from_bytes(&arr);
                    ids.push(Some(dalek_sk.verifying_key().to_bytes()));
                }
                (p, ids)
            } else {
                eprintln!("Warning: No --keys or --seeds provided. Generating random ephemeral keys.");
                eprintln!("(Note: Real running relays will reject packets unless their keys match! Pass --seeds 1,2,3 or --keys <hex,...>)");
                let p = (0..relay_addrs.len()).map(|_| {
                    let sk = X25519Secret::random_from_rng(rand::thread_rng());
                    *X25519Public::from(&sk).as_bytes()
                }).collect();
                (p, vec![None; relay_addrs.len()])
            };

            let mut route = Vec::new();
            println!("\nConfiguring {}-hop anonymous mix circuit:", relay_addrs.len());
            for (i, ((&addr, &pk_bytes), opt_id)) in relay_addrs.iter().zip(pks.iter()).zip(identity_pks.iter()).enumerate() {
                let is_last = i == relay_addrs.len() - 1;
                let flag = if is_last {
                    PacketFlag::FinalHop
                } else {
                    PacketFlag::Forward
                };

                let next_hop = if is_last {
                    addr
                } else {
                    relay_addrs[i + 1]
                };

                route.push(RouteHop {
                    routing: RoutingInfo {
                        next_hop,
                        delay_seed: 0,
                        flag,
                        reserved: 0,
                    },
                    public_key: pk_bytes,
                });

                let id_str = match opt_id {
                    Some(id) => format!(" (Verified Identity: {})", &hex::encode(id)[..16]),
                    None => String::new(),
                };
                println!("  Hop {}: {} (Public Key: {}){}", i + 1, addr, hex::encode(&pk_bytes), id_str);
            }

            let circuit = Circuit::new_with_entry(relay_addrs[0], route, 1);
            let packets = circuit.wrap_message_auto(message.as_bytes())?;

            println!(
                "Prepared {} Sphinx packet(s) (each {} bytes fixed)",
                packets.len(),
                prism_sphinx::PACKET_SIZE
            );

            // Send to the first relay with relay identity verification
            let transport = TransportClient::new(TransportConfig::default())?;
            for (addr, opt_id) in relay_addrs.iter().zip(identity_pks.iter()) {
                if let Some(id) = opt_id {
                    transport.add_expected_relay(*addr, *id).await;
                }
            }

            for (idx, packet) in packets.iter().enumerate() {
                let packet_bytes = packet.to_bytes();
                transport.send_packet(circuit.entry_address, &packet_bytes).await?;
                if packets.len() > 1 {
                    println!("Sent fragment packet {}/{} to entry relay", idx + 1, packets.len());
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            transport.close().await;

            println!("Message transmission complete to entry relay at {}", circuit.entry_address);
        }

        Command::Status => {
            println!("PRISM Client v{}", env!("CARGO_PKG_VERSION"));
            println!("Packet size: {} bytes", prism_sphinx::PACKET_SIZE);
            println!("Max payload: {} bytes", prism_sphinx::MAX_PAYLOAD_DATA);
            println!("Max hops: {}", prism_sphinx::MAX_HOPS);
        }
    }

    Ok(())
}
