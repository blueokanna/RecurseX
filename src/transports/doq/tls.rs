//! QUIC-TLS 1.3 client handshake (RFC 8446, RFC 9001 §8).
//!
//! This is the TLS half of the DoQ transport. It is deliberately *pure*:
//! no sockets, no QUIC packets. The QUIC transport ([`super::quic`])
//! feeds complete TLS handshake messages reassembled from CRYPTO frames
//! and reads back the messages to send. Keeping the handshake free of
//! transport concerns is what makes it testable and auditable.
//!
//! The module speaks the exact profile QUIC requires:
//!
//! * cipher suites `TLS_CHACHA20_POLY1305_SHA256` / `TLS_AES_128_GCM_SHA256`
//!   / `TLS_AES_256_GCM_SHA384`, X25519 key exchange;
//! * the `quic_transport_parameters` extension (type `0x0039`) carrying
//!   the client transport parameters (RFC 9000 §18.2);
//! * the `doq` ALPN (negotiated by the caller through [`ClientConfig`]);
//! * empty `legacy_session_id` (QUIC forbids session resumption); no
//!   0-RTT and no HelloRetryRequest retry (the offered group set always
//!   contains the group the server can pick).
//!
//! Secrets are derived with the TLS 1.3 key schedule (RFC 8446 §7.1) and
//! handed to the transport as raw traffic secrets; [`courierust`]'s
//! [`courierust::courierust_quic::protection::PacketKey::from_secret`]
//! expands them into QUIC packet-protection keys ("quic key" / "quic iv" /
//! "quic hp" labels).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use courierust::courierust_tls::crypto::ecdsa;
use courierust::courierust_tls::crypto::ed25519;
use courierust::courierust_tls::crypto::hash::{Digest, Sha256, Sha384};
use courierust::courierust_tls::crypto::hmac::{expand_label, extract as hkdf_extract, hmac};
use courierust::courierust_tls::crypto::rsa::{
    RsaPublicKey, DIGEST_INFO_SHA256, DIGEST_INFO_SHA384,
};
use courierust::courierust_tls::crypto::x25519;
use courierust::courierust_tls::x509::{self, RootStore};

use crate::error::{Error, ErrorKind, Result};

/// TLS 1.3 handshake message types (RFC 8446 §Appendix B.3).
mod hstype {
    pub const CLIENT_HELLO: u8 = 1;
    pub const SERVER_HELLO: u8 = 2;
    pub const ENCRYPTED_EXTENSIONS: u8 = 8;
    pub const CERTIFICATE: u8 = 11;
    pub const CERTIFICATE_VERIFY: u8 = 15;
    pub const FINISHED: u8 = 20;
}

/// TLS 1.3 cipher suites (RFC 8446 §Appendix B.4).
pub mod suite {
    /// TLS_AES_128_GCM_SHA256.
    pub const AES_128_GCM_SHA256: u16 = 0x1301;
    /// TLS_AES_256_GCM_SHA384.
    pub const AES_256_GCM_SHA384: u16 = 0x1302;
    /// TLS_CHACHA20_POLY1305_SHA256.
    pub const CHACHA20_POLY1305_SHA256: u16 = 0x1303;
}

/// TLS 1.3 signature schemes (RFC 8446 §4.2.3). Only schemes this
/// module can actually verify are offered.
mod sigscheme {
    /// rsa_pss_pss_sha256.
    pub const RSA_PSS_PSS_SHA256: u16 = 0x0809;
    /// rsa_pss_pss_sha384.
    pub const RSA_PSS_PSS_SHA384: u16 = 0x080a;
    /// rsa_pss_rsae_sha256.
    pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    /// rsa_pss_rsae_sha384.
    pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
    /// rsa_pkcs1_sha256.
    pub const RSA_PKCS1_SHA256: u16 = 0x0401;
    /// rsa_pkcs1_sha384.
    pub const RSA_PKCS1_SHA384: u16 = 0x0501;
    /// ecdsa_secp256r1_sha256.
    pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
    /// ecdsa_secp384r1_sha384.
    pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
    /// ed25519.
    pub const ED25519: u16 = 0x0807;
}

/// The RFC 8446 §4.2.2 `HelloRetryRequest` fixed random value
/// (`SHA-256("HelloRetryRequest")`). A server can only send this in
/// response to a ClientHello that does not contain a compatible group;
/// our ClientHello always offers X25519, so an HRR is a protocol error.
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe6, 0x86, 0x64, 0xb8, 0x24, 0x1a, 0x83, 0x76, 0x3c, 0x1f, 0x51, 0x70,
    0x2d, 0x7c, 0x1f, 0x0f, 0x1c, 0x7a, 0x05, 0x13, 0x05, 0x1f, 0x13, 0x91, 0xa0, 0x9c, 0x9e, 0x7e,
];

/// The length of the fixed context string in a CertificateVerify
/// signature (RFC 8446 §4.4.3: 64 octets of 0x20).
const CV_CONTEXT_PAD: usize = 64;

/// The digest length of a cipher suite's hash.
fn hash_len(suite: u16) -> usize {
    if suite == suite::AES_256_GCM_SHA384 {
        48
    } else {
        32
    }
}

/// A fresh digest for the suite's hash.
fn new_digest(suite: u16) -> Box<dyn Digest + Send> {
    if suite == suite::AES_256_GCM_SHA384 {
        Box::new(Sha384::new())
    } else {
        Box::new(Sha256::new())
    }
}

/// The empty hash of the suite's hash function.
fn empty_hash(suite: u16) -> Vec<u8> {
    let mut d = new_digest(suite);
    d.finalize()
}

/// Derive-Secret (RFC 8446 §7.1): `HKDF-Expand-Label(secret, label,
/// transcript_hash, Hash.length)`.
fn derive_secret(suite: u16, secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    let mut d = new_digest(suite);
    expand_label(d.as_mut(), secret, label, transcript_hash, hash_len(suite))
}

/// Wrap a handshake body in its 4-byte header
/// (`type || 3-byte big-endian length`). The transcript hashes the
/// message *with* this header (RFC 8446 §4.4.1).
fn hs_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

/// A TLS extension: `u16 type || u16 length || body`.
fn extension(ext_type: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

// ---------------------------------------------------------------------------
// Transport parameters (RFC 9000 §18.2)
// ---------------------------------------------------------------------------

/// The transport parameters a client advertises to the server.
#[derive(Debug, Clone)]
pub struct TransportParams {
    /// `max_idle_timeout` (ms) — 0 means no timeout.
    pub max_idle_timeout_ms: u64,
    /// `max_udp_payload_size` we accept.
    pub max_udp_payload_size: u64,
    /// `initial_max_data` — connection-level receive window.
    pub initial_max_data: u64,
    /// `initial_max_stream_data_bidi_local` — receive window on
    /// client-initiated bidirectional streams.
    pub initial_max_stream_data_bidi_local: u64,
    /// `initial_max_stream_data_bidi_remote` — receive window on
    /// server-initiated bidirectional streams.
    pub initial_max_stream_data_bidi_remote: u64,
    /// `initial_max_stream_data_uni` — receive window on
    /// server-initiated unidirectional streams (the DoQ session stream).
    pub initial_max_stream_data_uni: u64,
    /// `initial_max_streams_bidi` — server-initiated bidi streams allowed.
    pub initial_max_streams_bidi: u64,
    /// `initial_max_streams_uni` — server-initiated uni streams allowed.
    pub initial_max_streams_uni: u64,
    /// `active_connection_id_limit`.
    pub active_connection_id_limit: u64,
    /// `initial_source_connection_id` — our SCID on the first Initial.
    pub initial_source_connection_id: Vec<u8>,
    /// `retry_source_connection_id` — present only after a Retry.
    pub retry_source_connection_id: Option<Vec<u8>>,
}

impl TransportParams {
    /// Sensible DoQ client defaults: generous receive windows, a modest
    /// idle timeout, and room for the mandatory session stream. The
    /// values mirror courierust's H3 client (which is interop-tested
    /// against quinn/quiche peers).
    pub fn client_defaults(scid: Vec<u8>) -> Self {
        Self {
            max_idle_timeout_ms: 30_000,
            max_udp_payload_size: 1350,
            initial_max_data: 1 << 26,
            initial_max_stream_data_bidi_local: 1 << 20,
            initial_max_stream_data_bidi_remote: 1 << 20,
            initial_max_stream_data_uni: 1 << 20,
            initial_max_streams_bidi: 1024,
            initial_max_streams_uni: 16,
            active_connection_id_limit: 2,
            initial_source_connection_id: scid,
            retry_source_connection_id: None,
        }
    }

    /// Encode as a sequence of `varint(id) || varint(len) || value`.
    /// There is no outer length; the TLS extension length bounds it.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut put = |id: u64, value: &[u8]| {
            out.extend_from_slice(&courierust::courierust_quic::varint::encode(id));
            out.extend_from_slice(&courierust::courierust_quic::varint::encode(
                value.len() as u64
            ));
            out.extend_from_slice(value);
        };
        // Parameter IDs (RFC 9000 §18.2). Every value is itself a varint
        // except the connection-id parameters, which are raw bytes.
        if self.max_idle_timeout_ms > 0 {
            put(0x01, &varint_bytes(self.max_idle_timeout_ms));
        }
        put(0x03, &varint_bytes(self.max_udp_payload_size));
        put(0x04, &varint_bytes(self.initial_max_data));
        put(0x05, &varint_bytes(self.initial_max_stream_data_bidi_local));
        put(
            0x06,
            &varint_bytes(self.initial_max_stream_data_bidi_remote),
        );
        put(0x07, &varint_bytes(self.initial_max_stream_data_uni));
        put(0x08, &varint_bytes(self.initial_max_streams_bidi));
        put(0x09, &varint_bytes(self.initial_max_streams_uni));
        put(0x0e, &varint_bytes(self.active_connection_id_limit));
        put(0x0f, &self.initial_source_connection_id);
        if let Some(retry_scid) = &self.retry_source_connection_id {
            put(0x10, retry_scid);
        }
        out
    }
}

/// Varint-encode a `u64` (a small helper so `TransportParams::encode`
/// stays self-contained).
fn varint_bytes(v: u64) -> Vec<u8> {
    courierust::courierust_quic::varint::encode(v)
}

/// The server's transport parameters (the subset a DoQ client needs).
#[derive(Debug, Clone, Default)]
pub struct ServerTransportParams {
    /// `initial_max_data` (connection receive window the server allows).
    pub initial_max_data: u64,
    /// `initial_max_stream_data_bidi_local` — the server's receive
    /// window for data we send on our bidirectional streams.
    pub initial_max_stream_data_bidi_local: u64,
    /// `initial_max_streams_bidi` — streams we may open.
    pub initial_max_streams_bidi: u64,
    /// `initial_max_streams_uni` — streams the server may open.
    pub initial_max_streams_uni: u64,
    /// `original_destination_connection_id` (server must echo our DCID).
    pub original_destination_connection_id: Option<Vec<u8>>,
    /// `initial_source_connection_id` (server's SCID).
    pub initial_source_connection_id: Option<Vec<u8>>,
    /// `retry_source_connection_id` (present only after a Retry).
    pub retry_source_connection_id: Option<Vec<u8>>,
}

/// Decode a server transport-parameters block (the body of the
/// `0x0039` extension). Unknown parameters are skipped, not fatal.
pub fn decode_server_transport_params(bytes: &[u8]) -> Result<ServerTransportParams> {
    let mut out = ServerTransportParams::default();
    let mut pos = 0usize;
    while pos < bytes.len() {
        let (id, used) = courierust::courierust_quic::varint::decode(&bytes[pos..])
            .map_err(|_| Error::wire("QUIC transport parameter id malformed"))?;
        pos += used;
        let (len, used) = courierust::courierust_quic::varint::decode(&bytes[pos..])
            .map_err(|_| Error::wire("QUIC transport parameter length malformed"))?;
        pos += used;
        let len =
            usize::try_from(len).map_err(|_| Error::wire("QUIC parameter length overflow"))?;
        if pos + len > bytes.len() {
            return Err(Error::wire("QUIC transport parameter truncated"));
        }
        let value = &bytes[pos..pos + len];
        pos += len;
        match id {
            0x04 => out.initial_max_data = decode_param_u64(value)?,
            0x05 => out.initial_max_stream_data_bidi_local = decode_param_u64(value)?,
            0x08 => out.initial_max_streams_bidi = decode_param_u64(value)?,
            0x09 => out.initial_max_streams_uni = decode_param_u64(value)?,
            0x00 => out.original_destination_connection_id = Some(value.to_vec()),
            0x0f => out.initial_source_connection_id = Some(value.to_vec()),
            0x10 => out.retry_source_connection_id = Some(value.to_vec()),
            _ => {}
        }
    }
    Ok(out)
}

/// A transport-parameter value is a raw varint (RFC 9000 §18).
fn decode_param_u64(value: &[u8]) -> Result<u64> {
    let (v, used) = courierust::courierust_quic::varint::decode(value)
        .map_err(|_| Error::wire("QUIC transport parameter not a varint"))?;
    if used != value.len() {
        return Err(Error::wire("QUIC transport parameter has trailing bytes"));
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// Client handshake state machine
// ---------------------------------------------------------------------------

/// Configuration for a QUIC-TLS client handshake.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// ALPN protocol to offer (e.g. `b"doq"`).
    pub alpn: Vec<u8>,
    /// SNI server name (optional; most DoQ servers ignore it, but it is
    /// the correct thing to send when a hostname is known).
    pub server_name: Option<String>,
    /// Hostname the server certificate must match. `None` (with
    /// `verify`) disables the hostname check.
    pub hostname: Option<String>,
    /// Trust anchors. Empty store + `verify` = nothing is trusted.
    pub roots: RootStore,
    /// Whether to validate the certificate chain and hostname.
    pub verify: bool,
    /// Current Unix time (seconds) for certificate validity windows.
    pub now: i64,
    /// The transport parameters to advertise.
    pub transport_params: TransportParams,
}

/// The outcome of consuming the server's handshake flight.
#[derive(Debug)]
pub struct Completed {
    /// The client Finished message (header + body) to send in the
    /// Handshake packet-number space.
    pub client_finished: Vec<u8>,
    /// The negotiated cipher suite (wire value).
    pub suite: u16,
}

/// A client QUIC-TLS handshake in progress.
///
/// Feed it complete handshake messages (header + body, exactly as they
/// appear in CRYPTO frames) in wire order with [`ClientHandshake::feed`];
/// it parses, verifies, derives secrets, and finally reports
/// [`Completed`].
pub struct ClientHandshake {
    cfg: ClientConfig,
    random: [u8; 32],
    ecdhe_secret: [u8; 32],
    ecdhe_public: [u8; 32],
    /// All handshake messages seen so far (header + body), used to
    /// recompute the transcript with the negotiated hash.
    transcript_msgs: Vec<Vec<u8>>,
    /// Negotiated cipher suite (set after ServerHello).
    suite: Option<u16>,
    /// `handshake_secret` (RFC 8446 §7.1) once the ServerHello arrives.
    handshake_secret: Option<Vec<u8>>,
    c_hs: Option<Vec<u8>>,
    s_hs: Option<Vec<u8>>,
    c_ap: Option<Vec<u8>>,
    s_ap: Option<Vec<u8>>,
    /// Server transport parameters (from EncryptedExtensions).
    server_params: Option<ServerTransportParams>,
    saw_server_hello: bool,
    /// The ECDHE shared secret (set once the ServerHello is parsed).
    shared: [u8; 32],
    /// The next expected message type after ServerHello.
    next: u8,
    /// Server certificate chain (DER, leaf first), once received.
    chain: Vec<Vec<u8>>,
    done: bool,
}

impl fmt::Debug for ClientHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientHandshake")
            .field("suite", &self.suite)
            .field("saw_server_hello", &self.saw_server_hello)
            .field("next", &self.next)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl ClientHandshake {
    /// A fresh client handshake for the given configuration. Generates
    /// the X25519 key share and the 32-byte client random.
    pub fn new(cfg: ClientConfig) -> Self {
        let mut random = [0u8; 32];
        let mut rng = |buf: &mut [u8]| {
            if !courierust::courierust_tls::crypto::rng::fill_random(buf) {
                // Extremely unlikely; fill with a process-unique seed so
                // the handshake still proceeds (this is not secret
                // material by itself — the ECDHE private key below is
                // the secret, and it comes from the same source).
                let mut s = crate::entropy::seed_u64();
                for chunk in buf.chunks_mut(8) {
                    s = s
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    let bytes = s.to_le_bytes();
                    for (dst, src) in chunk.iter_mut().zip(bytes.iter()) {
                        *dst = *src;
                    }
                }
            }
        };
        rng(&mut random);
        let (ecdhe_secret, ecdhe_public) = x25519::keypair(&mut rng);
        Self {
            cfg,
            random,
            ecdhe_secret,
            ecdhe_public,
            transcript_msgs: Vec::new(),
            suite: None,
            handshake_secret: None,
            c_hs: None,
            s_hs: None,
            c_ap: None,
            s_ap: None,
            server_params: None,
            saw_server_hello: false,
            shared: [0u8; 32],
            next: hstype::ENCRYPTED_EXTENSIONS,
            chain: Vec::new(),
            done: false,
        }
    }

    /// The transcript hash of all messages fed so far, using the
    /// negotiated hash (SHA-256 before the suite is known).
    pub fn transcript_hash(&self) -> Vec<u8> {
        let suite = self.suite.unwrap_or(suite::AES_128_GCM_SHA256);
        let mut d = new_digest(suite);
        for m in &self.transcript_msgs {
            d.update(m);
        }
        d.finalize()
    }

    /// The client handshake traffic secret (for the Handshake write key).
    pub fn client_handshake_secret(&self) -> Option<&[u8]> {
        self.c_hs.as_deref()
    }

    /// The server handshake traffic secret (for the Handshake read key).
    pub fn server_handshake_secret(&self) -> Option<&[u8]> {
        self.s_hs.as_deref()
    }

    /// The client application traffic secret (1-RTT write key).
    pub fn client_application_secret(&self) -> Option<&[u8]> {
        self.c_ap.as_deref()
    }

    /// The server application traffic secret (1-RTT read key).
    pub fn server_application_secret(&self) -> Option<&[u8]> {
        self.s_ap.as_deref()
    }

    /// The negotiated cipher suite, once known.
    pub fn suite(&self) -> Option<u16> {
        self.suite
    }

    /// The server transport parameters, once received.
    pub fn server_params(&self) -> Option<&ServerTransportParams> {
        self.server_params.as_ref()
    }

    /// Whether the handshake has fully completed.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Build the ClientHello and record it in the transcript. The
    /// returned message (header + body) goes into CRYPTO frames of the
    /// first Initial packet.
    pub fn client_hello(&mut self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
        body.extend_from_slice(&self.random);
        body.push(0); // legacy_session_id: empty (mandatory for QUIC)
                      // cipher_suites
        body.extend_from_slice(&[0x00, 0x06]);
        body.extend_from_slice(&suite::CHACHA20_POLY1305_SHA256.to_be_bytes());
        body.extend_from_slice(&suite::AES_128_GCM_SHA256.to_be_bytes());
        body.extend_from_slice(&suite::AES_256_GCM_SHA384.to_be_bytes());
        // legacy_compression_methods
        body.extend_from_slice(&[0x01, 0x00]);

        let mut exts = Vec::new();
        // SNI (RFC 8446 §4.2.1): the server name, when known.
        if let Some(sni) = &self.cfg.server_name {
            if !sni.is_empty() {
                let name = sni.as_bytes();
                let mut server_name_list = Vec::with_capacity(3 + name.len());
                server_name_list.push(0); // host_name
                server_name_list.extend_from_slice(&(name.len() as u16).to_be_bytes());
                server_name_list.extend_from_slice(name);
                exts.extend_from_slice(&extension(0x0000, &{
                    let mut l = Vec::with_capacity(2 + server_name_list.len());
                    l.extend_from_slice(&(server_name_list.len() as u16).to_be_bytes());
                    l.extend_from_slice(&server_name_list);
                    l
                }));
            }
        }
        // supported_groups: X25519 (0x001d), secp256r1 (0x0017)
        let groups = [0x001du16, 0x0017];
        let mut gb = Vec::with_capacity(2 + groups.len() * 2);
        gb.extend_from_slice(&(groups.len() as u16 * 2).to_be_bytes());
        for g in groups {
            gb.extend_from_slice(&g.to_be_bytes());
        }
        exts.extend_from_slice(&extension(0x000a, &gb));
        // signature_algorithms (RFC 8446 §4.2.3). A broad list so any
        // server key type finds a matching scheme — a server whose
        // certificate key has no offered scheme sends handshake_failure.
        // Every offered scheme is one this module can verify (see
        // `verify_certificate_verify`).
        let sigs = [
            // PSS-PSS
            0x0809u16, 0x080a, // sha256, sha384
            // PSS-RSAE
            0x0804, 0x0805, // sha256, sha384
            // ECDSA
            0x0403, 0x0503, // P-256, P-384
            // Ed25519
            0x0807, // PKCS#1
            0x0401, 0x0501, // sha256, sha384
        ];
        let mut sb = Vec::with_capacity(2 + sigs.len() * 2);
        sb.extend_from_slice(&(sigs.len() as u16 * 2).to_be_bytes());
        for s in sigs {
            sb.extend_from_slice(&s.to_be_bytes());
        }
        exts.extend_from_slice(&extension(0x000d, &sb));
        // supported_versions: TLS 1.3 only
        exts.extend_from_slice(&extension(0x002b, &[0x02, 0x03, 0x04]));
        // key_share: one X25519 entry
        let mut kb = Vec::with_capacity(6 + 32);
        kb.extend_from_slice(&0x0024u16.to_be_bytes()); // total length (2+2+32)
        kb.extend_from_slice(&0x001du16.to_be_bytes()); // group
        kb.extend_from_slice(&32u16.to_be_bytes());
        kb.extend_from_slice(&self.ecdhe_public);
        exts.extend_from_slice(&extension(0x0033, &kb));
        // ALPN
        if !self.cfg.alpn.is_empty() {
            let mut ab = Vec::with_capacity(2 + 1 + self.cfg.alpn.len());
            ab.extend_from_slice(&(1 + self.cfg.alpn.len() as u16).to_be_bytes());
            ab.push(self.cfg.alpn.len() as u8);
            ab.extend_from_slice(&self.cfg.alpn);
            exts.extend_from_slice(&extension(0x0010, &ab));
        }
        // quic_transport_parameters (RFC 9001 §8.2)
        let params = self.cfg.transport_params.encode();
        exts.extend_from_slice(&extension(0x0039, &params));

        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let msg = hs_message(hstype::CLIENT_HELLO, &body);
        self.transcript_msgs.push(msg.clone());
        msg
    }

    /// Feed one complete handshake message (header + body, exactly as it
    /// arrives in a CRYPTO frame). Returns `Some(Completed)` when the
    /// handshake finishes (right after the server Finished is verified).
    pub fn feed(&mut self, msg: &[u8]) -> Result<Option<Completed>> {
        if msg.len() < 4 {
            return Err(Error::wire("TLS handshake message too short"));
        }
        let msg_type = msg[0];
        let len = u32::from_be_bytes([0, msg[1], msg[2], msg[3]]) as usize;
        if 4 + len != msg.len() {
            return Err(Error::wire("TLS handshake message length mismatch"));
        }
        let body = &msg[4..];
        match msg_type {
            hstype::SERVER_HELLO if !self.saw_server_hello => {
                self.parse_server_hello(body)?;
                // The ServerHello becomes part of the transcript before
                // the handshake traffic secrets are derived: RFC 8446
                // §7.1 hashes `ClientHello..ServerHello` for the
                // "c/s hs traffic" labels. Deriving from CH alone
                // produces keys that do not match the peer's.
                self.transcript_msgs.push(msg.to_vec());
                self.derive_handshake_secrets()?;
                Ok(None)
            }
            hstype::ENCRYPTED_EXTENSIONS | hstype::CERTIFICATE | hstype::CERTIFICATE_VERIFY
                if self.saw_server_hello =>
            {
                if msg_type != self.next {
                    return Err(Error::wire("TLS handshake messages out of order"));
                }
                match msg_type {
                    hstype::ENCRYPTED_EXTENSIONS => {
                        self.server_params = Some(self.parse_encrypted_extensions(body)?);
                        self.next = hstype::CERTIFICATE;
                    }
                    hstype::CERTIFICATE => {
                        self.chain = parse_certificate_list(body)?;
                        self.next = hstype::CERTIFICATE_VERIFY;
                    }
                    hstype::CERTIFICATE_VERIFY => {
                        let hash_before_cv = self.transcript_hash();
                        self.verify_certificate_verify(body, &hash_before_cv)?;
                        self.next = hstype::FINISHED;
                    }
                    _ => unreachable!(),
                }
                self.transcript_msgs.push(msg.to_vec());
                Ok(None)
            }
            hstype::FINISHED if self.saw_server_hello => {
                if self.next != hstype::FINISHED {
                    return Err(Error::wire("TLS handshake messages out of order"));
                }
                let hash_before_finished = self.transcript_hash();
                self.verify_server_finished(body, &hash_before_finished)?;
                self.transcript_msgs.push(msg.to_vec());
                let client_finished = self.derive_application_secrets();
                self.done = true;
                Ok(Some(Completed {
                    client_finished,
                    suite: self.suite.expect("suite set before Finished"),
                }))
            }
            _ => Err(Error::wire("unexpected TLS handshake message")),
        }
    }

    fn parse_server_hello(&mut self, body: &[u8]) -> Result<()> {
        // legacy_version must be 0x0303.
        if body.len() < 35 {
            return Err(Error::wire("ServerHello too short"));
        }
        if body[0] != 0x03 || body[1] != 0x03 {
            return Err(Error::wire("ServerHello legacy version is not TLS 1.2"));
        }
        let random = &body[2..34];
        if random == HRR_RANDOM {
            return Err(Error::wire(
                "HelloRetryRequest received (server group mismatch; refusing to retry)",
            ));
        }
        let sid_len = body[34] as usize;
        let mut pos = 35usize;
        if sid_len != 0 {
            return Err(Error::wire(
                "ServerHello legacy_session_id is not empty (QUIC forbids resumption)",
            ));
        }
        pos += sid_len;
        if pos + 3 > body.len() {
            return Err(Error::wire("ServerHello truncated"));
        }
        let suite = u16::from_be_bytes([body[pos], body[pos + 1]]);
        pos += 2;
        if body[pos] != 0 {
            return Err(Error::wire("ServerHello compression method is not null"));
        }
        pos += 1;
        if !matches!(
            suite,
            suite::AES_128_GCM_SHA256 | suite::AES_256_GCM_SHA384 | suite::CHACHA20_POLY1305_SHA256
        ) {
            return Err(Error::wire(
                "ServerHello selected an unsupported cipher suite",
            ));
        }
        // Extensions: must contain supported_versions=0x0304 and key_share.
        if pos + 2 > body.len() {
            return Err(Error::wire("ServerHello missing extensions"));
        }
        let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        if pos + ext_total > body.len() {
            return Err(Error::wire("ServerHello extensions truncated"));
        }
        let mut server_key_share: Option<[u8; 32]> = None;
        let mut saw_versions = false;
        let mut ep = pos;
        let end = pos + ext_total;
        while ep + 4 <= end {
            let etype = u16::from_be_bytes([body[ep], body[ep + 1]]);
            let elen = u16::from_be_bytes([body[ep + 2], body[ep + 3]]) as usize;
            ep += 4;
            if ep + elen > end {
                return Err(Error::wire("ServerHello extension truncated"));
            }
            let ev = &body[ep..ep + elen];
            match etype {
                0x002b => {
                    // supported_versions in a ServerHello is a single
                    // u16 `selected_version` (RFC 8446 §4.2.1) — unlike
                    // the ClientHello, which carries a length-prefixed
                    // list. It must be exactly TLS 1.3 (0x0304).
                    if elen == 2 && ev[0] == 0x03 && ev[1] == 0x04 {
                        saw_versions = true;
                    }
                }
                0x0033
                    // key_share: u16 group || u16 len || key. A guard keeps
                    // a malformed extension from overwriting a good one.
                    if elen >= 4 + 32
                        && ev[0] == 0x00
                        && ev[1] == 0x1d
                        && ev[2] == 0x00
                        && ev[3] == 0x20 =>
                {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&ev[4..36]);
                    server_key_share = Some(k);
                }
                _ => {}
            }
            ep += elen;
        }
        if !saw_versions {
            return Err(Error::wire("ServerHello missing supported_versions"));
        }
        let server_pub =
            server_key_share.ok_or_else(|| Error::wire("ServerHello missing X25519 key share"))?;
        let shared = x25519::x25519(&self.ecdhe_secret, &server_pub);
        if shared.iter().all(|&b| b == 0) {
            return Err(Error::wire("ServerHello produced an all-zero ECDHE secret"));
        }
        self.suite = Some(suite);
        self.shared = shared;
        self.saw_server_hello = true;
        Ok(())
    }

    /// Derive the handshake traffic secrets (RFC 8446 §7.1). Must be
    /// called after the ServerHello is added to the transcript, so the
    /// transcript hash covers `ClientHello..ServerHello`.
    fn derive_handshake_secrets(&mut self) -> Result<()> {
        let suite = self.suite.expect("suite set before handshake secrets");
        let h = hash_len(suite);
        let zeros = vec![0u8; h];
        let mut d0 = new_digest(suite);
        let early = hkdf_extract(d0.as_mut(), &zeros, &zeros);
        let derived = derive_secret(suite, &early, b"derived", &empty_hash(suite));
        let mut d1 = new_digest(suite);
        let handshake_secret = hkdf_extract(d1.as_mut(), &derived, &self.shared);
        let ch_sh = self.transcript_hash(); // CH..SH (SH already pushed)
        let c_hs = derive_secret(suite, &handshake_secret, b"c hs traffic", &ch_sh);
        let s_hs = derive_secret(suite, &handshake_secret, b"s hs traffic", &ch_sh);
        self.handshake_secret = Some(handshake_secret);
        self.c_hs = Some(c_hs);
        self.s_hs = Some(s_hs);
        Ok(())
    }

    fn parse_encrypted_extensions(&self, body: &[u8]) -> Result<ServerTransportParams> {
        let mut pos = 0usize;
        if pos + 2 > body.len() {
            return Err(Error::wire("EncryptedExtensions truncated"));
        }
        let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        if pos + ext_total > body.len() {
            return Err(Error::wire("EncryptedExtensions truncated"));
        }
        let end = pos + ext_total;
        let mut params = None;
        while pos + 4 <= end {
            let etype = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let elen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
            pos += 4;
            if pos + elen > end {
                return Err(Error::wire("EncryptedExtensions extension truncated"));
            }
            if etype == 0x0039 {
                params = Some(decode_server_transport_params(&body[pos..pos + elen])?);
            }
            pos += elen;
        }
        params.ok_or_else(|| Error::wire("server omitted quic_transport_parameters"))
    }

    fn verify_certificate_verify(&self, body: &[u8], hash_before_cv: &[u8]) -> Result<()> {
        if body.len() < 4 {
            return Err(Error::wire("CertificateVerify truncated"));
        }
        let scheme = u16::from_be_bytes([body[0], body[1]]);
        let sig_len = u16::from_be_bytes([body[2], body[3]]) as usize;
        if 4 + sig_len != body.len() {
            return Err(Error::wire("CertificateVerify signature length mismatch"));
        }
        let signature = &body[4..];
        if self.chain.is_empty() {
            return Err(Error::wire("CertificateVerify before any certificate"));
        }
        let leaf_der = &self.chain[0];
        let leaf = x509::parse_certificate(leaf_der).map_err(|e| {
            Error::new(
                ErrorKind::Dnssec,
                format!("cannot parse leaf certificate: {e}"),
            )
        })?;

        // Validate the chain and hostname before touching the signature.
        self.validate_certificate(&leaf)?;

        // The signature input (RFC 8446 §4.4.3): 64 spaces, context
        // string, 0x00, then the transcript hash up to (not including)
        // CertificateVerify.
        let mut content = Vec::with_capacity(CV_CONTEXT_PAD + 34 + hash_before_cv.len());
        content.extend(std::iter::repeat(0x20u8).take(CV_CONTEXT_PAD));
        content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        content.push(0);
        content.extend_from_slice(hash_before_cv);

        let suite = self.suite.expect("suite set before CertificateVerify");
        let ok = match scheme {
            // rsa_pss_pss_* verifies with the same PSS math as
            // rsa_pss_rsae_*; the scheme only signals how the key's
            // SPKI AlgorithmIdentifier is framed (RFC 8446 §4.2.3).
            sigscheme::RSA_PSS_PSS_SHA256 | sigscheme::RSA_PSS_RSAE_SHA256 => {
                let key = self.leaf_rsa_key(&leaf)?;
                key.verify_pss(&mut Sha256::new(), &content, 32, signature)
            }
            sigscheme::RSA_PSS_PSS_SHA384 | sigscheme::RSA_PSS_RSAE_SHA384 => {
                let key = self.leaf_rsa_key(&leaf)?;
                key.verify_pss(&mut Sha384::new(), &content, 48, signature)
            }
            sigscheme::RSA_PKCS1_SHA256 => {
                let key = self.leaf_rsa_key(&leaf)?;
                let digest = {
                    let mut d = Sha256::new();
                    d.update(&content);
                    d.finalize()
                };
                key.verify_pkcs1v15(DIGEST_INFO_SHA256, &digest, signature)
            }
            sigscheme::RSA_PKCS1_SHA384 => {
                let key = self.leaf_rsa_key(&leaf)?;
                let digest = {
                    let mut d = Sha384::new();
                    d.update(&content);
                    d.finalize()
                };
                key.verify_pkcs1v15(DIGEST_INFO_SHA384, &digest, signature)
            }
            sigscheme::ECDSA_SECP256R1_SHA256 => {
                if suite != suite::AES_128_GCM_SHA256 && suite != suite::CHACHA20_POLY1305_SHA256 {
                    return Err(Error::new(
                        ErrorKind::Dnssec,
                        "ECDSA P-256 scheme with a SHA-384 suite",
                    ));
                }
                let (qx, qy) = self.leaf_ec_point(&leaf, ecdsa::Curve::P256)?;
                let digest = {
                    let mut d = Sha256::new();
                    d.update(&content);
                    d.finalize()
                };
                ecdsa::verify_der(ecdsa::Curve::P256, &qx, &qy, &digest, signature)
            }
            sigscheme::ECDSA_SECP384R1_SHA384 => {
                if suite != suite::AES_256_GCM_SHA384 {
                    return Err(Error::new(
                        ErrorKind::Dnssec,
                        "ECDSA P-384 scheme with a SHA-256 suite",
                    ));
                }
                let (qx, qy) = self.leaf_ec_point(&leaf, ecdsa::Curve::P384)?;
                let digest = {
                    let mut d = Sha384::new();
                    d.update(&content);
                    d.finalize()
                };
                ecdsa::verify_der(ecdsa::Curve::P384, &qx, &qy, &digest, signature)
            }
            sigscheme::ED25519 => {
                if leaf.spki.key.len() != 32 {
                    return Err(Error::new(
                        ErrorKind::Dnssec,
                        "Ed25519 certificate key is not 32 bytes",
                    ));
                }
                if signature.len() != 64 {
                    return Err(Error::new(
                        ErrorKind::Dnssec,
                        "Ed25519 signature is not 64 bytes",
                    ));
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&leaf.spki.key);
                let mut sig = [0u8; 64];
                sig.copy_from_slice(signature);
                ed25519::verify(&pk, &content, &sig)
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Dnssec,
                    "unsupported CertificateVerify signature scheme",
                ))
            }
        };
        if !ok {
            return Err(Error::new(
                ErrorKind::Dnssec,
                "CertificateVerify signature did not verify",
            ));
        }
        Ok(())
    }

    fn verify_server_finished(&self, body: &[u8], hash_before_finished: &[u8]) -> Result<()> {
        let suite = self.suite.expect("suite set before Finished");
        let h = hash_len(suite);
        if body.len() != h {
            return Err(Error::wire("server Finished has the wrong length"));
        }
        let s_hs = self
            .s_hs
            .as_deref()
            .ok_or_else(|| Error::wire("server Finished before handshake secrets"))?;
        let mut d = new_digest(suite);
        let finished_key = expand_label(d.as_mut(), s_hs, b"finished", &[], h);
        let mut md = new_digest(suite);
        let verify_data = hmac(md.as_mut(), &finished_key, hash_before_finished);
        if verify_data.as_slice() != body {
            return Err(Error::new(
                ErrorKind::Dnssec,
                "server Finished did not verify",
            ));
        }
        Ok(())
    }

    fn derive_application_secrets(&mut self) -> Vec<u8> {
        let suite = self.suite.expect("suite set before application secrets");
        let h = hash_len(suite);
        let hs = self
            .handshake_secret
            .as_deref()
            .expect("handshake secret set");
        let derived = derive_secret(suite, hs, b"derived", &empty_hash(suite));
        let zeros = vec![0u8; h];
        let mut d = new_digest(suite);
        let master = hkdf_extract(d.as_mut(), &derived, &zeros);
        let ch_to_sf = self.transcript_hash(); // CH..server Finished (inclusive)
        let c_ap = derive_secret(suite, &master, b"c ap traffic", &ch_to_sf);
        let s_ap = derive_secret(suite, &master, b"s ap traffic", &ch_to_sf);
        // Client Finished: transcript includes the server Finished.
        let mut fd = new_digest(suite);
        let finished_key = expand_label(
            fd.as_mut(),
            self.c_hs.as_deref().unwrap(),
            b"finished",
            &[],
            h,
        );
        let mut md = new_digest(suite);
        let verify_data = hmac(md.as_mut(), &finished_key, &ch_to_sf);
        self.c_ap = Some(c_ap);
        self.s_ap = Some(s_ap);
        hs_message(hstype::FINISHED, &verify_data)
    }

    fn validate_certificate(&self, leaf: &x509::Certificate) -> Result<()> {
        if !self.cfg.verify {
            return Ok(());
        }
        x509::validate_chain(&self.cfg.roots, &self.chain, self.cfg.now).map_err(|e| {
            Error::new(
                ErrorKind::Dnssec,
                format!("certificate chain rejected: {e}"),
            )
        })?;
        if !x509::has_server_auth_eku(leaf) {
            return Err(Error::new(
                ErrorKind::Dnssec,
                "leaf certificate lacks serverAuth EKU",
            ));
        }
        if let Some(hostname) = &self.cfg.hostname {
            if !x509::hostname_matches(hostname, &leaf.dns_names, &leaf.ip_names) {
                return Err(Error::new(
                    ErrorKind::Dnssec,
                    format!("certificate does not match hostname {hostname}"),
                ));
            }
        }
        Ok(())
    }

    fn leaf_rsa_key(&self, leaf: &x509::Certificate) -> Result<RsaPublicKey> {
        let (n, e) = parse_rsa_public_key(&leaf.spki.key).ok_or_else(|| {
            Error::new(
                ErrorKind::Dnssec,
                "leaf certificate is not a usable RSA key",
            )
        })?;
        Ok(RsaPublicKey { n, e })
    }

    fn leaf_ec_point(
        &self,
        leaf: &x509::Certificate,
        curve: ecdsa::Curve,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let clen = match curve {
            ecdsa::Curve::P256 => 32,
            ecdsa::Curve::P384 => 48,
            ecdsa::Curve::P521 => 66,
        };
        if leaf.spki.ec_curve != Some(curve) {
            return Err(Error::new(
                ErrorKind::Dnssec,
                "leaf certificate curve mismatch",
            ));
        }
        let key = &leaf.spki.key;
        if key.len() != 1 + 2 * clen || key[0] != 0x04 {
            return Err(Error::new(
                ErrorKind::Dnssec,
                "leaf certificate key is not an uncompressed EC point",
            ));
        }
        Ok((key[1..1 + clen].to_vec(), key[1 + clen..].to_vec()))
    }
}

/// Parse an RFC 5280 `RSAPublicKey` (`SEQUENCE { INTEGER n, INTEGER e }`)
/// from the DER bytes in `spki.key`, stripping the positive-sign leading
/// zero from each INTEGER.
fn parse_rsa_public_key(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (tag, content, consumed) = read_der_tlv(der)?;
    if tag != 0x30 {
        return None;
    }
    let _ = consumed;
    let (tag_n, n_raw, n_used) = read_der_tlv(content)?;
    if tag_n != 0x02 {
        return None;
    }
    let (tag_e, e_raw, _) = read_der_tlv(&content[n_used..])?;
    if tag_e != 0x02 {
        return None;
    }
    let n = strip_int_leading_zero(n_raw);
    let e = strip_int_leading_zero(e_raw);
    if n.is_empty() || e.is_empty() {
        return None;
    }
    Some((n, e))
}

/// Remove a single leading `0x00` sign byte from an INTEGER value.
fn strip_int_leading_zero(v: &[u8]) -> Vec<u8> {
    if v.len() > 1 && v[0] == 0 {
        v[1..].to_vec()
    } else {
        v.to_vec()
    }
}

/// Read one DER TLV: returns `(tag, value, total_consumed)`.
fn read_der_tlv(data: &[u8]) -> Option<(u8, &[u8], usize)> {
    if data.is_empty() {
        return None;
    }
    let tag = data[0];
    let mut pos = 1usize;
    if pos >= data.len() {
        return None;
    }
    let first_len = data[pos];
    pos += 1;
    let len = if first_len & 0x80 == 0 {
        first_len as usize
    } else {
        let nbytes = (first_len & 0x7f) as usize;
        if nbytes == 0 || nbytes > 4 || pos + nbytes > data.len() {
            return None;
        }
        let mut l = 0usize;
        for &b in &data[pos..pos + nbytes] {
            l = (l << 8) | b as usize;
        }
        pos += nbytes;
        l
    };
    if pos + len > data.len() {
        return None;
    }
    Some((tag, &data[pos..pos + len], pos + len))
}

/// Parse an RFC 8446 §4.4.2 Certificate message body into the DER chain
/// (leaf first). The message must carry no request context.
pub fn parse_certificate_list(body: &[u8]) -> Result<Vec<Vec<u8>>> {
    if body.is_empty() {
        return Err(Error::wire("Certificate message empty"));
    }
    let ctx_len = body[0] as usize;
    if ctx_len != 0 {
        return Err(Error::wire("Certificate carries a request context"));
    }
    let mut pos = 1usize;
    if pos + 3 > body.len() {
        return Err(Error::wire("Certificate list length truncated"));
    }
    let list_len =
        ((body[pos] as usize) << 16) | ((body[pos + 1] as usize) << 8) | (body[pos + 2] as usize);
    pos += 3;
    let end = pos + list_len;
    if end > body.len() {
        return Err(Error::wire("Certificate list truncated"));
    }
    let mut chain = Vec::new();
    while pos < end {
        if pos + 3 > end {
            return Err(Error::wire("Certificate entry length truncated"));
        }
        let cert_len = ((body[pos] as usize) << 16)
            | ((body[pos + 1] as usize) << 8)
            | (body[pos + 2] as usize);
        pos += 3;
        if pos + cert_len > end {
            return Err(Error::wire("Certificate entry truncated"));
        }
        chain.push(body[pos..pos + cert_len].to_vec());
        pos += cert_len;
        if pos + 2 > end {
            return Err(Error::wire("Certificate entry extensions truncated"));
        }
        let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        if pos + ext_len > end {
            return Err(Error::wire("Certificate entry extensions truncated"));
        }
        pos += ext_len;
    }
    if chain.is_empty() {
        return Err(Error::wire("Certificate message has no certificates"));
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_params_roundtrip() {
        let scid = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let tp = TransportParams::client_defaults(scid.clone());
        let enc = tp.encode();
        // A client block starts with max_idle_timeout (id 0x01).
        assert_eq!(enc[0], 0x01);
        // Decode it back with the server-side decoder: the parameters we
        // advertise must parse cleanly and carry the expected values.
        let parsed = decode_server_transport_params(&enc).unwrap();
        assert_eq!(parsed.initial_max_data, tp.initial_max_data);
        assert_eq!(
            parsed.initial_max_stream_data_bidi_local,
            tp.initial_max_stream_data_bidi_local
        );
        assert_eq!(parsed.initial_max_streams_uni, tp.initial_max_streams_uni);
        assert_eq!(
            parsed.initial_source_connection_id.as_deref(),
            Some(scid.as_slice())
        );
    }

    #[test]
    fn client_hello_has_expected_structure() {
        let cfg = ClientConfig {
            alpn: b"doq".to_vec(),
            server_name: Some("dns.example.test".into()),
            hostname: Some("dns.example.test".into()),
            roots: RootStore::new(),
            verify: false,
            now: 1_700_000_000,
            transport_params: TransportParams::client_defaults(vec![1, 2, 3, 4, 5, 6, 7, 8]),
        };
        let mut hs = ClientHandshake::new(cfg);
        let ch = hs.client_hello();
        // Header: type 1, length.
        assert_eq!(ch[0], 1);
        let len = u32::from_be_bytes([0, ch[1], ch[2], ch[3]]) as usize;
        assert_eq!(len + 4, ch.len());
        let body = &ch[4..];
        // legacy_version, random(32), empty session id.
        assert_eq!(&body[0..2], &[0x03, 0x03]);
        assert_eq!(body[34], 0);
        // cipher suites length = 6.
        assert_eq!(&body[35..37], &[0x00, 0x06]);
        // Find the ALPN extension and confirm it carries "doq".
        // Layout: version(2) random(32) sid(1) suite_len(2) suites(6)
        // compression_len(1) method(1) ext_len(2) extensions...
        let ext_start = 45;
        let ext_total = u16::from_be_bytes([body[ext_start], body[ext_start + 1]]) as usize;
        let exts = &body[ext_start + 2..ext_start + 2 + ext_total];
        let mut found_doq = false;
        let mut found_qtp = false;
        let mut p = 0;
        while p + 4 <= exts.len() {
            let et = u16::from_be_bytes([exts[p], exts[p + 1]]);
            let el = u16::from_be_bytes([exts[p + 2], exts[p + 3]]) as usize;
            let v = &exts[p + 4..p + 4 + el];
            if et == 0x0010 {
                // ALPN body: u16 list len, then (u8 len, proto).
                found_doq =
                    v.len() == 6 && v[0] == 0x00 && v[1] == 0x04 && v[2] == 3 && &v[3..6] == b"doq";
            }
            if et == 0x0039 {
                found_qtp = !v.is_empty();
            }
            p += 4 + el;
        }
        assert!(found_doq, "ALPN extension must carry doq");
        assert!(
            found_qtp,
            "quic_transport_parameters extension must be present"
        );
    }

    #[test]
    fn certificate_list_parse() {
        // Minimal: ctx_len=0, list_len=6, one entry (3-byte len, 1-byte
        // cert, 2-byte ext len).
        let body = [0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0xAA, 0x00, 0x00];
        let chain = parse_certificate_list(&body).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0], vec![0xAA]);
    }
}
