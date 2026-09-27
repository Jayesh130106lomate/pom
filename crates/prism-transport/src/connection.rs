//! QUIC connection management for PRISM.
//!
//! Provides client and server abstractions for sending and receiving
//! fixed-size Sphinx packets over QUIC connections with cryptographic
//! relay identity verification, ingress DoS protection, and rate limiting.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig as QuinnTransportConfig, VarInt};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info, warn};

use crate::errors::TransportError;

/// Configuration for transport endpoints.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Local bind address.
    pub bind_addr: SocketAddr,
    /// Expected Sphinx packet size.
    pub packet_size: usize,
    /// Maximum concurrent connections globally.
    pub max_connections: usize,
    /// Maximum concurrent connections per remote IP.
    pub max_connections_per_ip: usize,
    /// Per-IP packet rate limit in packets per second.
    pub rate_limit_per_ip_pps: f64,
    /// Global ingress rate limit in packets per second.
    pub global_rate_limit_pps: f64,
    /// Burst multiplier for token buckets.
    pub burst_factor: f64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        TransportConfig {
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            packet_size: 32_768, // PACKET_SIZE
            max_connections: 1024,
            max_connections_per_ip: 32,
            rate_limit_per_ip_pps: 250.0,
            global_rate_limit_pps: 5000.0,
            burst_factor: 2.0,
        }
    }
}

/// Operational and overload metrics for QUIC transport endpoints.
#[derive(Debug, Default)]
pub struct TransportMetrics {
    /// Currently active inbound QUIC connections.
    pub active_connections: AtomicUsize,
    /// Total incoming connections rejected by admission control.
    pub connections_rejected: AtomicU64,
    /// Total packets dropped by rate limiters (global or per-IP).
    pub packets_dropped_rate_limit: AtomicU64,
    /// Total packets dropped due to buffer backpressure / channel overload.
    pub packets_dropped_backpressure: AtomicU64,
}

/// Token bucket algorithm for high-performance packet rate limiting.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_update: Instant,
}

impl TokenBucket {
    fn new(rate: f64, burst_factor: f64) -> Self {
        let max_tokens = (rate * burst_factor).max(1.0);
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate: rate,
            last_update: Instant::now(),
        }
    }

    fn try_consume(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_update).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_update = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// State for ingress rate limiting and connection tracking.
struct RateLimiterState {
    global_bucket: TokenBucket,
    ip_buckets: HashMap<IpAddr, TokenBucket>,
    ip_connections: HashMap<IpAddr, usize>,
    last_prune: Instant,
}

impl RateLimiterState {
    fn prune_idle(&mut self, now: Instant) {
        self.ip_buckets.retain(|_, bucket| {
            now.saturating_duration_since(bucket.last_update) < Duration::from_secs(30)
        });
    }
}

/// Generate an X.509 certificate bound to an Ed25519 relay identity key.
pub fn generate_relay_cert(
    identity_seed: Option<&[u8; 32]>,
) -> Result<
    (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
        [u8; 32],
    ),
    TransportError,
> {
    let key_pair = if let Some(seed) = identity_seed {
        let mut pkcs8 = Vec::with_capacity(48);
        pkcs8.extend_from_slice(&[
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ]);
        pkcs8.extend_from_slice(seed);
        rcgen::KeyPair::try_from(pkcs8.as_slice())
            .map_err(|e| TransportError::TlsError(format!("ed25519 pkcs8 parsing: {}", e)))?
    } else {
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| TransportError::TlsError(format!("keypair generation: {}", e)))?
    };

    let mut public_key = [0u8; 32];
    let raw_pk = key_pair.public_key_raw();
    if raw_pk.len() == 32 {
        public_key.copy_from_slice(raw_pk);
    } else {
        return Err(TransportError::TlsError(
            "invalid raw ed25519 public key length".into(),
        ));
    }

    let hex_pk = hex::encode(public_key);
    let san_names = vec![
        "prism-relay".to_string(),
        "localhost".to_string(),
        format!("r-{}.{}.prism", &hex_pk[..32], &hex_pk[32..]),
    ];

    let mut params = rcgen::CertificateParams::new(san_names)
        .map_err(|e| TransportError::TlsError(format!("cert params: {}", e)))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, format!("relay-{}", &hex_pk[..8]));

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| TransportError::TlsError(format!("cert signing: {}", e)))?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| TransportError::TlsError(format!("key conversion: {}", e)))?;

    Ok((cert_der, key_der, public_key))
}

/// Extract the raw 32-byte Ed25519 public key from an X.509 DER certificate.
pub fn extract_ed25519_pubkey(cert_der: &[u8]) -> Option<[u8; 32]> {
    // SubjectPublicKeyInfo for Ed25519 in DER format:
    // 30 05 06 03 2b 65 70 03 21 00 <32-byte-key>
    let pattern = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    for i in 0..cert_der.len().saturating_sub(pattern.len() + 32) {
        if &cert_der[i..i + pattern.len()] == &pattern {
            let key_start = i + pattern.len();
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&cert_der[key_start..key_start + 32]);
            return Some(pk);
        }
    }
    None
}

/// QUIC transport server — listens for incoming connections and receives packets.
pub struct TransportServer {
    endpoint: Endpoint,
    config: TransportConfig,
    public_identity: [u8; 32],
    metrics: Arc<TransportMetrics>,
}

impl TransportServer {
    /// Create and bind a new transport server with an ephemeral identity key.
    pub fn new(config: TransportConfig) -> Result<Self, TransportError> {
        Self::new_with_identity(config, None)
    }

    /// Create and bind a new transport server bound to a specific Ed25519 identity seed.
    pub fn new_with_identity(
        config: TransportConfig,
        identity_seed: Option<&[u8; 32]>,
    ) -> Result<Self, TransportError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cert, key, public_identity) = generate_relay_cert(identity_seed)?;

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| TransportError::TlsError(format!("server config: {}", e)))?;

        server_crypto.alpn_protocols = vec![b"prism/1".to_vec()];

        let mut quic_transport = QuinnTransportConfig::default();
        quic_transport.max_concurrent_uni_streams(VarInt::from_u32(2048));

        let mut server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|e| TransportError::TlsError(format!("quic server config: {}", e)))?,
        ));
        server_config.transport_config(Arc::new(quic_transport));

        let endpoint = Endpoint::server(server_config, config.bind_addr)
            .map_err(|e| TransportError::BindFailed(format!("{}", e)))?;

        info!("Transport server bound to {}", endpoint.local_addr().unwrap());

        Ok(TransportServer {
            endpoint,
            config,
            public_identity,
            metrics: Arc::new(TransportMetrics::default()),
        })
    }

    /// Get the local address this server is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint
            .local_addr()
            .map_err(|e| TransportError::BindFailed(format!("{}", e)))
    }

    /// Get the Ed25519 public identity key of this transport server.
    pub fn public_identity(&self) -> [u8; 32] {
        self.public_identity
    }

    /// Get a handle to the transport server metrics.
    pub fn metrics(&self) -> Arc<TransportMetrics> {
        self.metrics.clone()
    }

    /// Accept incoming connections and forward received packets to the channel.
    pub async fn run(
        &self,
        packet_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    ) -> Result<(), TransportError> {
        info!("Transport server listening for connections");

        let rate_limiter = Arc::new(Mutex::new(RateLimiterState {
            global_bucket: TokenBucket::new(
                self.config.global_rate_limit_pps,
                self.config.burst_factor,
            ),
            ip_buckets: HashMap::new(),
            ip_connections: HashMap::new(),
            last_prune: Instant::now(),
        }));

        while let Some(incoming) = self.endpoint.accept().await {
            let remote_ip = incoming.remote_address().ip();
            let active_conns = self.metrics.active_connections.load(Ordering::Relaxed);

            // 1. Global connection admission check
            if active_conns >= self.config.max_connections {
                self.metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                warn!(
                    "Rejecting connection from {}: global max_connections ({}) reached",
                    remote_ip, self.config.max_connections
                );
                incoming.refuse();
                continue;
            }

            // 2. Per-IP connection admission check
            {
                let mut rl = rate_limiter.lock().await;
                let ip_conns = rl.ip_connections.entry(remote_ip).or_insert(0);
                if *ip_conns >= self.config.max_connections_per_ip {
                    self.metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "Rejecting connection from {}: per-IP limit ({}) reached",
                        remote_ip, self.config.max_connections_per_ip
                    );
                    incoming.refuse();
                    continue;
                }
                *ip_conns += 1;
            }

            self.metrics.active_connections.fetch_add(1, Ordering::Relaxed);

            let tx = packet_tx.clone();
            let packet_size = self.config.packet_size;
            let metrics = self.metrics.clone();
            let rl_conn = rate_limiter.clone();
            let per_ip_limit = self.config.rate_limit_per_ip_pps;
            let burst_factor = self.config.burst_factor;

            tokio::spawn(async move {
                let conn_res = incoming.await;
                match conn_res {
                    Ok(connection) => {
                        let remote = connection.remote_address();
                        debug!("Accepted connection from {}", remote);

                        while let Ok(mut recv) = connection.accept_uni().await {
                            let tx = tx.clone();
                            let metrics = metrics.clone();
                            let rl = rl_conn.clone();

                            tokio::spawn(async move {
                                let mut buf = vec![0u8; packet_size];
                                let read_result = tokio::time::timeout(
                                    Duration::from_secs(15),
                                    recv.read_exact(&mut buf),
                                )
                                .await;

                                match read_result {
                                    Ok(Ok(())) => {
                                        let now = Instant::now();

                                        // Two-tier rate limiter check
                                        let allowed = {
                                            let mut r = rl.lock().await;
                                            if now.saturating_duration_since(r.last_prune)
                                                >= Duration::from_secs(10)
                                            {
                                                r.prune_idle(now);
                                                r.last_prune = now;
                                            }

                                            let global_ok = r.global_bucket.try_consume(now);
                                            let ip_bucket = r
                                                .ip_buckets
                                                .entry(remote_ip)
                                                .or_insert_with(|| {
                                                    TokenBucket::new(per_ip_limit, burst_factor)
                                                });
                                            let ip_ok = ip_bucket.try_consume(now);

                                            global_ok && ip_ok
                                        };

                                        if !allowed {
                                            metrics
                                                .packets_dropped_rate_limit
                                                .fetch_add(1, Ordering::Relaxed);
                                            debug!(
                                                "Packet dropped: rate limit exceeded for {}",
                                                remote
                                            );
                                            return;
                                        }

                                        // Backpressure and overload detection (>85% queue depth)
                                        let cap = tx.capacity();
                                        let max_cap = tx.max_capacity();
                                        let threshold = (max_cap * 15 / 100).max(1);
                                        if cap < threshold {
                                            metrics
                                                .packets_dropped_backpressure
                                                .fetch_add(1, Ordering::Relaxed);
                                            warn!(
                                                "Packet dropped: buffer backpressure threshold (>85%) exceeded"
                                            );
                                            return;
                                        }

                                        if tx.try_send((remote, buf)).is_err() {
                                            metrics
                                                .packets_dropped_backpressure
                                                .fetch_add(1, Ordering::Relaxed);
                                            warn!("Packet dropped: channel full");
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        debug!("Read error from {}: {}", remote, e);
                                    }
                                    Err(_) => {
                                        debug!("Stream read timed out from {}", remote);
                                    }
                                }
                            });
                        }
                    }
                    Err(e) => {
                        warn!("Failed to accept connection: {}", e);
                    }
                }

                // Connection closed: decrement connection metrics
                metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
                let mut r = rl_conn.lock().await;
                if let Some(c) = r.ip_connections.get_mut(&remote_ip) {
                    *c = c.saturating_sub(1);
                    if *c == 0 {
                        r.ip_connections.remove(&remote_ip);
                    }
                }
            });
        }

        Ok(())
    }

    /// Shut down the server.
    pub fn shutdown(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
    }
}

/// Cryptographic relay identity verifier implementing `rustls::client::danger::ServerCertVerifier`.
/// Verifies that peer relay certificates are bound to the expected Ed25519 identity key.
#[derive(Debug, Default)]
pub struct RelayIdentityVerifier {
    expected_identities: std::sync::RwLock<HashMap<String, [u8; 32]>>,
    pinned_keys: std::sync::RwLock<HashSet<[u8; 32]>>,
}

impl RelayIdentityVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_expected_identity(&self, identifier: String, key: [u8; 32]) {
        self.expected_identities
            .write()
            .unwrap()
            .insert(identifier, key);
        self.pinned_keys.write().unwrap().insert(key);
    }

    pub fn is_empty(&self) -> bool {
        self.expected_identities.read().unwrap().is_empty()
            && self.pinned_keys.read().unwrap().is_empty()
    }
}

impl rustls::client::danger::ServerCertVerifier for RelayIdentityVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let actual_pk = extract_ed25519_pubkey(end_entity.as_ref()).ok_or_else(|| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        let name_str = match server_name {
            rustls::pki_types::ServerName::DnsName(dns) => dns.as_ref().to_string(),
            rustls::pki_types::ServerName::IpAddress(ip) => match ip {
                rustls::pki_types::IpAddr::V4(v4) => std::net::Ipv4Addr::from(*v4).to_string(),
                rustls::pki_types::IpAddr::V6(v6) => std::net::Ipv6Addr::from(*v6).to_string(),
            },
            _ => String::new(),
        };

        // 1. Check if an explicit expected identity is registered for this address/name
        let map = self.expected_identities.read().unwrap();
        if let Some(&expected_pk) = map.get(&name_str) {
            if actual_pk != expected_pk {
                warn!(
                    "Relay identity verification failed for {}: expected {}, got {}",
                    name_str,
                    hex::encode(expected_pk),
                    hex::encode(actual_pk)
                );
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        // 2. Check if server_name is formatted as "r-<part1>.<part2>.prism"
        if let Some(rest) = name_str
            .strip_prefix("r-")
            .and_then(|s| s.strip_suffix(".prism"))
        {
            let hex_key = rest.replace('.', "");
            match hex::decode(&hex_key) {
                Ok(expected_pk_vec) if expected_pk_vec.len() == 32 => {
                    if actual_pk != expected_pk_vec.as_slice() {
                        warn!(
                            "Relay identity mismatch for {}: expected {}, got {}",
                            name_str,
                            hex_key,
                            hex::encode(actual_pk)
                        );
                        return Err(rustls::Error::InvalidCertificate(
                            rustls::CertificateError::ApplicationVerificationFailure,
                        ));
                    }
                    return Ok(rustls::client::danger::ServerCertVerified::assertion());
                }
                _ => {
                    warn!("Invalid hex key in relay server name: {}", name_str);
                    return Err(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::ApplicationVerificationFailure,
                    ));
                }
            }
        }

        // 3. If pinned keys are specified, require membership
        let pinned = self.pinned_keys.read().unwrap();
        if !pinned.is_empty() {
            if !pinned.contains(&actual_pk) {
                warn!(
                    "Relay identity key {} not in pinned set",
                    hex::encode(actual_pk)
                );
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer,
                ));
            }
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        // If explicit expected identities are registered but this target name wasn't found, reject
        if !map.is_empty() {
            warn!("Relay identity not registered for {}", name_str);
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

/// QUIC transport client — connects to relays and sends packets.
pub struct TransportClient {
    endpoint: Endpoint,
    connections: RwLock<HashMap<SocketAddr, quinn::Connection>>,
    expected_relays: RwLock<HashMap<SocketAddr, [u8; 32]>>,
    verifier: Arc<RelayIdentityVerifier>,
    #[allow(dead_code)]
    config: TransportConfig,
}

impl TransportClient {
    /// Create a new transport client with relay identity verification enabled.
    pub fn new(config: TransportConfig) -> Result<Self, TransportError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let verifier = Arc::new(RelayIdentityVerifier::new());

        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();

        client_crypto.alpn_protocols = vec![b"prism/1".to_vec()];

        let mut quic_transport = QuinnTransportConfig::default();
        quic_transport.max_concurrent_uni_streams(VarInt::from_u32(2048));

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
                .map_err(|e| TransportError::TlsError(format!("quic client config: {}", e)))?,
        ));
        client_config.transport_config(Arc::new(quic_transport));

        let mut endpoint = Endpoint::client(config.bind_addr)
            .map_err(|e| TransportError::BindFailed(format!("{}", e)))?;

        endpoint.set_default_client_config(client_config);

        Ok(TransportClient {
            endpoint,
            connections: RwLock::new(HashMap::new()),
            expected_relays: RwLock::new(HashMap::new()),
            verifier,
            config,
        })
    }

    /// Register a trusted relay identity key for an address.
    pub async fn add_expected_relay(&self, target: SocketAddr, identity_key: [u8; 32]) {
        let mut conns = self.expected_relays.write().await;
        conns.insert(target, identity_key);
        let hex_pk = hex::encode(identity_key);
        self.verifier
            .add_expected_identity(target.to_string(), identity_key);
        self.verifier
            .add_expected_identity(target.ip().to_string(), identity_key);
        self.verifier.add_expected_identity(
            format!("r-{}.{}.prism", &hex_pk[..32], &hex_pk[32..]),
            identity_key,
        );
    }

    /// Access the underlying verifier.
    pub fn verifier(&self) -> Arc<RelayIdentityVerifier> {
        self.verifier.clone()
    }

    /// Get or establish a pooled QUIC connection to the target relay.
    pub async fn get_or_connect(
        &self,
        target: SocketAddr,
    ) -> Result<quinn::Connection, TransportError> {
        {
            let conns = self.connections.read().await;
            if let Some(conn) = conns.get(&target) {
                if conn.close_reason().is_none() {
                    return Ok(conn.clone());
                }
            }
        }

        let server_name = {
            let relays = self.expected_relays.read().await;
            if let Some(&pk) = relays.get(&target) {
                let hex_pk = hex::encode(pk);
                format!("r-{}.{}.prism", &hex_pk[..32], &hex_pk[32..])
            } else {
                "prism-relay".to_string()
            }
        };

        // Establish connection without blocking other targets in the connection pool
        let new_conn = self
            .endpoint
            .connect(target, &server_name)
            .map_err(|e| TransportError::ConnectionFailed(format!("{}", e)))?
            .await
            .map_err(|e| TransportError::ConnectionFailed(format!("{}", e)))?;

        let mut conns = self.connections.write().await;
        if let Some(existing) = conns.get(&target) {
            if existing.close_reason().is_none() {
                new_conn.close(0u32.into(), b"redundant");
                return Ok(existing.clone());
            }
        }
        conns.insert(target, new_conn.clone());
        Ok(new_conn)
    }

    /// Send a single Sphinx packet to a relay using pooled QUIC connection.
    pub async fn send_packet(
        &self,
        target: SocketAddr,
        packet: &[u8],
    ) -> Result<(), TransportError> {
        let connection = self.get_or_connect(target).await?;

        let mut send = connection
            .open_uni()
            .await
            .map_err(|e| TransportError::SendFailed(format!("open stream: {}", e)))?;

        send.write_all(packet)
            .await
            .map_err(|e| TransportError::SendFailed(format!("write: {}", e)))?;

        send.finish()
            .map_err(|e| TransportError::SendFailed(format!("finish: {}", e)))?;

        Ok(())
    }

    /// Send a batch of packets to the same target relay over multiplexed QUIC streams.
    pub async fn send_packets_batch(
        &self,
        target: SocketAddr,
        packets: &[Vec<u8>],
    ) -> Result<(), TransportError> {
        if packets.is_empty() {
            return Ok(());
        }
        if packets.len() == 1 {
            return self.send_packet(target, &packets[0]).await;
        }

        let connection = self.get_or_connect(target).await?;
        let mut set = tokio::task::JoinSet::new();

        for packet in packets {
            let conn = connection.clone();
            let p = packet.clone();
            set.spawn(async move {
                let mut send = conn
                    .open_uni()
                    .await
                    .map_err(|e| TransportError::SendFailed(format!("open stream: {}", e)))?;

                send.write_all(&p)
                    .await
                    .map_err(|e| TransportError::SendFailed(format!("write: {}", e)))?;

                send.finish()
                    .map_err(|e| TransportError::SendFailed(format!("finish: {}", e)))?;

                Ok::<(), TransportError>(())
            });
        }

        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(e) => {
                    return Err(TransportError::SendFailed(format!("task join error: {}", e)))
                }
            }
        }

        Ok(())
    }

    /// Wait for all outgoing connections to complete before shutting down.
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }

    /// Gracefully close all open connections and wait for endpoint to idle.
    pub async fn close(&self) {
        {
            let mut conns = self.connections.write().await;
            for (_, conn) in conns.drain() {
                conn.close(0u32.into(), b"done");
            }
        }
        self.endpoint.wait_idle().await;
    }

    /// Shut down the client.
    pub fn shutdown(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_relay_cert_with_identity_seed() {
        let seed = [42u8; 32];
        let (cert, _key, pk) = generate_relay_cert(Some(&seed)).unwrap();
        let dalek_sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let expected_pk = dalek_sk.verifying_key().to_bytes();
        assert_eq!(
            pk, expected_pk,
            "Derived public key must match ed25519_dalek verifying key"
        );

        let extracted =
            extract_ed25519_pubkey(cert.as_ref()).expect("must extract pubkey from cert");
        assert_eq!(
            extracted, expected_pk,
            "Extracted public key must match expected key"
        );
    }
}
