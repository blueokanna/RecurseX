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
use crate::wire::WireBytes;

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

/// The X25519 key share carried by a `key_share` extension body
/// (`u16 group || u16 len || key`), or `None` for anything this client cannot
/// use. A share that is absent, malformed, or for another group is *ignored*
/// rather than fatal, so the handshake fails later with the honest reason
/// ("no usable key share") instead of a parse error that hides the cause.
/// Reading through [`WireBytes`] is what makes the short cases values rather
/// than panics.
fn x25519_key_share(body: &[u8]) -> Option<[u8; 32]> {
    // `x25519` (group 0x001d) with a 32-octet key (RFC 8446 §4.2.8.2).
    const X25519_WITH_32_OCTET_KEY: [u8; 4] = [0x00, 0x1d, 0x00, 0x20];
    if body.array_at::<4>(0).ok()? != X25519_WITH_32_OCTET_KEY {
        return None;
    }
    body.array_at::<32>(4).ok()
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
        let (id, used) = courierust::courierust_quic::varint::decode(bytes.rest_at(pos)?)
            .map_err(|_| Error::wire("QUIC transport parameter id malformed"))?;
        pos += used;
        let (len, used) = courierust::courierust_quic::varint::decode(bytes.rest_at(pos)?)
            .map_err(|_| Error::wire("QUIC transport parameter length malformed"))?;
        pos += used;
        let len =
            usize::try_from(len).map_err(|_| Error::wire("QUIC parameter length overflow"))?;
        // The bound is checked by the read itself: `slice_at` reports a length
        // that runs past the end, and it reports it through arithmetic that
        // cannot overflow rather than a comparison that can wrap.
        let value = bytes
            .slice_at(pos, len)
            .map_err(|_| Error::wire("QUIC transport parameter truncated"))?;
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
        let msg_type = msg.byte_at(0)?;
        // A handshake length is three octets (RFC 8446 §4). Read as a `u32` and
        // masked it would be one bad edit away from consuming `msg[4]`, which
        // is the first byte of the body it is supposed to describe.
        let len = (u32::from_be_bytes([
            0,
            msg.byte_at(1)?,
            msg.byte_at(2)?,
            msg.byte_at(3)?,
        ])) as usize;
        if 4 + len != msg.len() {
            return Err(Error::wire("TLS handshake message length mismatch"));
        }
        let body = msg.rest_at(4)?;
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
        if body.byte_at(0)? != 0x03 || body.byte_at(1)? != 0x03 {
            return Err(Error::wire("ServerHello legacy version is not TLS 1.2"));
        }
        let random = body.slice_at(2, 32)?;
        if random == HRR_RANDOM {
            return Err(Error::wire(
                "HelloRetryRequest received (server group mismatch; refusing to retry)",
            ));
        }
        let sid_len = usize::from(body.byte_at(34)?);
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
        let suite = body.u16_at(pos)?;
        pos += 2;
        if body.byte_at(pos)? != 0 {
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
        let ext_total = usize::from(body.u16_at(pos)?);
        pos += 2;
        if pos + ext_total > body.len() {
            return Err(Error::wire("ServerHello extensions truncated"));
        }
        let mut server_key_share: Option<[u8; 32]> = None;
        let mut saw_versions = false;
        let mut ep = pos;
        let end = pos + ext_total;
        while ep + 4 <= end {
            let etype = body.u16_at(ep)?;
            let elen = usize::from(body.u16_at(ep + 2)?);
            ep += 4;
            let ev = body
                .slice_at(ep, elen)
                .map_err(|_| Error::wire("ServerHello extension truncated"))?;
            match etype {
                0x002b => {
                    // supported_versions in a ServerHello is a single
                    // u16 `selected_version` (RFC 8446 §4.2.1) — unlike
                    // the ClientHello, which carries a length-prefixed
                    // list. It must be exactly TLS 1.3 (0x0304).
                    if elen == 2 && matches!(ev.array_at::<2>(0), Ok([0x03, 0x04])) {
                        saw_versions = true;
                    }
                }
                0x0033 => {
                    // Only an x25519 share is usable; a malformed extension is
                    // ignored rather than trusted, so a wrong share surfaces
                    // as a missing one — the honest diagnosis.
                    if let Some(k) = x25519_key_share(ev) {
                        server_key_share = Some(k);
                    }
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
        let ext_total = usize::from(body.u16_at(pos)?);
        pos += 2;
        if pos + ext_total > body.len() {
            return Err(Error::wire("EncryptedExtensions truncated"));
        }
        let end = pos + ext_total;
        let mut params = None;
        while pos + 4 <= end {
            let etype = body.u16_at(pos)?;
            let elen = usize::from(body.u16_at(pos + 2)?);
            pos += 4;
            let extension = body
                .slice_at(pos, elen)
                .map_err(|_| Error::wire("EncryptedExtensions extension truncated"))?;
            if etype == 0x0039 {
                params = Some(decode_server_transport_params(extension)?);
            }
            pos += elen;
        }
        params.ok_or_else(|| Error::wire("server omitted quic_transport_parameters"))
    }

    fn verify_certificate_verify(&self, body: &[u8], hash_before_cv: &[u8]) -> Result<()> {
        if body.len() < 4 {
            return Err(Error::wire("CertificateVerify truncated"));
        }
        let scheme = body.u16_at(0)?;
        let sig_len = usize::from(body.u16_at(2)?);
        if 4 + sig_len != body.len() {
            return Err(Error::wire("CertificateVerify signature length mismatch"));
        }
        let signature = body.rest_at(4)?;
        let leaf_der = self
            .chain
            .first()
            .ok_or_else(|| Error::wire("CertificateVerify before any certificate"))?;
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
        // An uncompressed EC point is `0x04 || X || Y`. A truncated key fails
        // the leading-byte read and the length check for the same reason, so
        // they share one error: `matches!` keeps a short key from turning into
        // a propagated "read past the end", which would send the reader looking
        // for a buffer bug instead of at the certificate.
        if key.len() != 1 + 2 * clen || !matches!(key.byte_at(0), Ok(0x04)) {
            return Err(Error::new(
                ErrorKind::Dnssec,
                "leaf certificate key is not an uncompressed EC point",
            ));
        }
        Ok((
            key.slice_at(1, clen)?.to_vec(),
            key.rest_at(1 + clen)?.to_vec(),
        ))
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
    let (tag_e, e_raw, _) = read_der_tlv(content.rest_at(n_used).ok()?)?;
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

/// Remove a single leading `0x00` sign byte from an INTEGER value. A lone
/// `0x00` is the encoding of zero itself and is kept.
fn strip_int_leading_zero(v: &[u8]) -> Vec<u8> {
    match v.split_first() {
        Some((0, rest)) if !rest.is_empty() => rest.to_vec(),
        _ => v.to_vec(),
    }
}

/// Read one DER TLV: returns `(tag, value, total_consumed)`.
///
/// A value shorter than the length it declares is a truncation, which is `None`
/// — this parser has no error type because every failure in DER is the same
/// failure: the bytes are not what they claim to be.
fn read_der_tlv(data: &[u8]) -> Option<(u8, &[u8], usize)> {
    let (tag, rest) = data.split_first()?;
    let (first_len, rest) = rest.split_first()?;
    // A short-form length is at most 127 and lives in the octet itself; a
    // long-form length carries the number of length octets in its low seven
    // bits (X.690 §8.1.3). The indefinite form is not DER and is not accepted.
    let (len, body_at) = if first_len & 0x80 == 0 {
        (usize::from(*first_len), 0usize)
    } else {
        let nbytes = usize::from(first_len & 0x7f);
        if nbytes == 0 || nbytes > 4 {
            return None;
        }
        let mut len = 0usize;
        for &byte in rest.get(..nbytes)? {
            len = (len << 8) | usize::from(byte);
        }
        (len, nbytes)
    };
    // A length that reaches past the end is a truncation, and one that stops
    // short is fine: `total_consumed` is what lets a caller walk a sequence.
    let value = rest.get(body_at..)?.get(..len)?;
    Some((*tag, value, 2 + body_at + len))
}

/// Parse an RFC 8446 §4.4.2 Certificate message body into the DER chain
/// (leaf first). The message must carry no request context.
pub fn parse_certificate_list(body: &[u8]) -> Result<Vec<Vec<u8>>> {
    // `u8 context_len || u24 list_len || entries`. QUIC always sends an empty
    // context (RFC 9001 §8.2); a non-empty one belongs to a resumption
    // handshake over a byte stream and has no meaning here.
    let ctx_len = usize::from(
        body.first()
            .copied()
            .ok_or_else(|| Error::wire("Certificate message empty"))?,
    );
    if ctx_len != 0 {
        return Err(Error::wire("Certificate carries a request context"));
    }
    let list_len = usize::try_from(
        body.u24_at(1)
            .map_err(|_| Error::wire("Certificate list length truncated"))?,
    )
    .map_err(|_| Error::wire("Certificate list length overflow"))?;
    // Parse the list as its own buffer, which is what it is. Every entry offset
    // is then bounded by the list rather than by the message, so a length that
    // runs past the list is a truncation even though the message continues.
    let list = body
        .slice_at(4, list_len)
        .map_err(|_| Error::wire("Certificate list truncated"))?;
    let mut pos = 0usize;
    let mut chain = Vec::new();
    while pos < list.len() {
        let cert_len = usize::try_from(
            list.u24_at(pos)
                .map_err(|_| Error::wire("Certificate entry length truncated"))?,
        )
        .map_err(|_| Error::wire("Certificate entry length overflow"))?;
        pos += 3;
        chain.push(
            list.slice_at(pos, cert_len)
                .map_err(|_| Error::wire("Certificate entry truncated"))?
                .to_vec(),
        );
        pos += cert_len;
        // The entry extensions (`u16 len || bytes`) are not interpreted, but
        // they must be present and inside the list. Skipping them is still a
        // read, so it is still checked.
        let ext_len = usize::from(
            list.u16_at(pos)
                .map_err(|_| Error::wire("Certificate entry extensions truncated"))?,
        );
        list.slice_at(pos + 2, ext_len)
            .map_err(|_| Error::wire("Certificate entry extensions truncated"))?;
        pos += 2 + ext_len;
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

    #[test]
    fn a_certificate_entry_is_bounded_by_the_list_not_the_message() {
        // list_len = 6, entry claims a 8-octet certificate, and the message
        // carries eight more bytes after the list. The trailing bytes are the
        // point: a parser that bounded entries by the *message* would accept
        // this and hand the caller bytes belonging to the next handshake
        // message, so this test fails if that bound is ever loosened.
        let mut past_list = vec![0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x08, 0xAA, 0xAA, 0xAA];
        past_list.extend_from_slice(&[0xBB; 8]);
        assert!(parse_certificate_list(&past_list).is_err());

        // A list that claims to be longer than the message.
        let overlong = vec![0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01, 0xAA, 0x00, 0x00];
        assert!(parse_certificate_list(&overlong).is_err());

        // An entry with no room for its own length field.
        assert!(parse_certificate_list(&[0x00, 0x00, 0x00, 0x02, 0x00, 0x00]).is_err());
        // Entry extensions that run past the list.
        assert!(parse_certificate_list(&[0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0xAA, 0x00, 0x10])
            .is_err());

        // A non-empty request context belongs to a stream handshake.
        assert!(parse_certificate_list(&[0x01, 0x00, 0x00, 0x00]).is_err());
        // Nothing at all, and a list with no entries.
        assert!(parse_certificate_list(&[]).is_err());
        assert!(parse_certificate_list(&[0x00, 0x00, 0x00, 0x00]).is_err());
        // Truncated inside the list-length field.
        assert!(parse_certificate_list(&[0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn a_handshake_length_is_three_octets() {
        // RFC 8446 §4: a handshake length is three octets. Reading it as four
        // consumes the first body byte, which is not a subtle failure — every
        // message would be one byte short and the transcript would not match
        // the peer's.
        let body = vec![0xAAu8; 198];
        let msg = hs_message(1, &body);
        assert_eq!(msg.len(), 202);
        assert_eq!(msg.u24_at(1).unwrap() as usize, body.len());
        // 198 == 0x0000c6: the fourth octet of the 4-octet form is absent.
        assert_eq!(&msg[1..4], &[0x00, 0x00, 0xc6]);
        assert_eq!(msg.first(), Some(&1u8));
    }

    #[test]
    fn der_tlv_reads_both_length_forms_and_refuses_truncation() {
        // Short form.
        assert_eq!(
            read_der_tlv(&[0x30, 0x03, 0x01, 0x02, 0x03]).unwrap(),
            (0x30, &[0x01, 0x02, 0x03][..], 5)
        );
        // Long form: 0x81 says one length octet follows.
        assert_eq!(
            read_der_tlv(&[0x04, 0x81, 0x02, 0xAA, 0xBB]).unwrap(),
            (0x04, &[0xAA, 0xBB][..], 5)
        );
        // A value shorter than its length is a truncation, not a short read.
        assert!(read_der_tlv(&[0x30, 0x04, 0x01]).is_none());
        // A long-form length that needs octets the buffer does not have.
        assert!(read_der_tlv(&[0x30, 0x82, 0x01]).is_none());
        // The indefinite form is not DER.
        assert!(read_der_tlv(&[0x30, 0x80, 0x00, 0x00]).is_none());
        // A tag with no length, and nothing at all.
        assert!(read_der_tlv(&[0x30]).is_none());
        assert!(read_der_tlv(&[]).is_none());
        // Trailing bytes are left alone: `total_consumed` is what lets a caller
        // walk a SEQUENCE.
        let (_, value, used) = read_der_tlv(&[0x02, 0x01, 0x05, 0x02, 0x01, 0x03]).unwrap();
        assert_eq!((value, used), (&[0x05][..], 3));
    }

    #[test]
    fn an_integer_sign_byte_is_stripped_but_zero_is_kept() {
        assert_eq!(strip_int_leading_zero(&[0x00, 0x05]), vec![0x05]);
        // A lone `0x00` is the encoding of zero, not a sign byte.
        assert_eq!(strip_int_leading_zero(&[0x00]), vec![0x00]);
        // Exactly one byte is a sign byte.
        assert_eq!(strip_int_leading_zero(&[0x00, 0x00, 0x05]), vec![0x00, 0x05]);
        // No leading zero: the bytes are the value.
        assert_eq!(strip_int_leading_zero(&[0x7F]), vec![0x7F]);
        assert_eq!(strip_int_leading_zero(&[0x80, 0x01]), vec![0x80, 0x01]);
        assert_eq!(strip_int_leading_zero(&[]), Vec::<u8>::new());
    }

    #[test]
    fn rsa_public_key_der_parses_and_refuses_truncation() {
        // SEQUENCE { INTEGER 5, INTEGER 3 }.
        let (n, e) =
            parse_rsa_public_key(&[0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x03]).unwrap();
        assert_eq!((n, e), (vec![0x05], vec![0x03]));

        // With the positive-sign octet on the modulus.
        let (n, _) = parse_rsa_public_key(&[
            0x30, 0x07, 0x02, 0x02, 0x00, 0x05, 0x02, 0x01, 0x03,
        ])
        .unwrap();
        assert_eq!(n, vec![0x05]);

        // Declared two octets, one present.
        assert!(parse_rsa_public_key(&[0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x02, 0x03]).is_none());
        // Not a SEQUENCE.
        assert!(parse_rsa_public_key(&[0x31, 0x03, 0x02, 0x01, 0x05]).is_none());
        // Truncated before the exponent.
        assert!(parse_rsa_public_key(&[0x30, 0x03, 0x02, 0x01, 0x05]).is_none());
        // A zero-length modulus is not a key.
        assert!(parse_rsa_public_key(&[0x30, 0x04, 0x02, 0x00, 0x02, 0x01, 0x03]).is_none());
        assert!(parse_rsa_public_key(&[]).is_none());
    }

    #[test]
    fn a_truncated_transport_parameter_is_refused_not_read() {
        // id 0x03 claims eight octets with none present.
        assert!(decode_server_transport_params(&[0x03, 0x08]).is_err());
        // A length that overflows the buffer.
        assert!(decode_server_transport_params(&[0x03, 0xff, 0x01]).is_err());
        // A length field with no value behind it.
        assert!(decode_server_transport_params(&[0x03, 0x01]).is_err());
        // An unknown parameter is skipped, not fatal, and the one after it is
        // still read.
        let mut params = vec![0x42, 0x01, 0x00];
        params.extend_from_slice(&[0x04, 0x01, 0x10]);
        assert_eq!(
            decode_server_transport_params(&params).unwrap().initial_max_data,
            0x10
        );
    }

    #[test]
    fn only_an_x25519_key_share_is_accepted() {
        let mut offered = vec![0x00, 0x1d, 0x00, 0x20];
        offered.extend_from_slice(&[0x09; 32]);
        assert_eq!(x25519_key_share(&offered).unwrap(), [0x09; 32]);

        // Another group (secp256r1 is 0x0017) with a plausible length.
        let mut other_group = vec![0x00, 0x17, 0x00, 0x20];
        other_group.extend_from_slice(&[0x09; 32]);
        assert!(x25519_key_share(&other_group).is_none());

        // The right group, but the length behind it is not 32.
        let mut wrong_length = vec![0x00, 0x1d, 0x00, 0x1f];
        wrong_length.extend_from_slice(&[0x09; 31]);
        assert!(x25519_key_share(&wrong_length).is_none());

        // The header has to be *at* offset zero; four bytes that look like it
        // elsewhere are not a key share.
        let mut shifted = vec![0x00, 0x00, 0x1d, 0x00, 0x20];
        shifted.extend_from_slice(&[0x09; 32]);
        assert!(x25519_key_share(&shifted).is_none());

        assert!(x25519_key_share(&[]).is_none());
        assert!(x25519_key_share(&[0x00, 0x1d, 0x00]).is_none());
    }

    /// A ServerHello body whose `supported_versions` extension carries
    /// `selected_version` and whose `key_share` carries `key_share`, so the
    /// extension scanners can be exercised without inventing a whole
    /// handshake.
    fn server_hello_body(selected_version: &[u8], key_share: &[u8]) -> Vec<u8> {
        let mut ext = Vec::new();
        // supported_versions: a single u16 in a ServerHello (RFC 8446 §4.2.1).
        ext.extend_from_slice(&[0x00, 0x2b]);
        ext.extend_from_slice(&(selected_version.len() as u16).to_be_bytes());
        ext.extend_from_slice(selected_version);
        ext.extend_from_slice(&[0x00, 0x33]);
        ext.extend_from_slice(&((key_share.len() + 4) as u16).to_be_bytes());
        ext.extend_from_slice(&[0x00, 0x1d]);
        ext.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
        ext.extend_from_slice(key_share);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x5A; 32]); // random, not the HRR constant
        body.push(0x00); // empty legacy_session_id
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(0x00); // null compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        body
    }

    #[test]
    fn a_server_hello_needs_a_usable_x25519_key_share() {
        const TLS13: &[u8] = &[0x03, 0x04];
        let cfg = ClientConfig {
            alpn: b"doq".to_vec(),
            server_name: Some("dns.example.test".into()),
            hostname: Some("dns.example.test".into()),
            roots: RootStore::new(),
            verify: false,
            now: 1_700_000_000,
            transport_params: TransportParams::client_defaults(vec![1, 2, 3, 4, 5, 6, 7, 8]),
        };
        // 0x09 followed by zeros is the x25519 base point: a legal peer public
        // key whose shared secret is never all-zero.
        let mut base_point = [0u8; 32];
        base_point[0] = 9;

        let mut handshake = ClientHandshake::new(cfg.clone());
        handshake
            .parse_server_hello(&server_hello_body(TLS13, &base_point))
            .expect("an x25519 ServerHello must be accepted");
        assert_eq!(handshake.suite(), Some(suite::AES_128_GCM_SHA256));

        // Thirty-one octets: the group check sees a length it did not offer, so
        // the extension is ignored and the failure names the missing key share
        // rather than reporting a length error somewhere else.
        let mut short_key = ClientHandshake::new(cfg.clone());
        let err = short_key
            .parse_server_hello(&server_hello_body(TLS13, &base_point[..31]))
            .expect_err("a 31-octet key share is not x25519 with 32 octets");
        assert_eq!(err.kind, ErrorKind::Wire);

        // The extension block claims more bytes than the body has.
        let mut truncated = server_hello_body(TLS13, &base_point);
        truncated.truncate(truncated.len() - 3);
        let mut cut = ClientHandshake::new(cfg.clone());
        assert!(cut.parse_server_hello(&truncated).is_err());

        // A server that selects TLS 1.2 has not selected TLS 1.3.
        let mut downgrade = ClientHandshake::new(cfg);
        assert!(downgrade
            .parse_server_hello(&server_hello_body(&[0x03, 0x03], &base_point))
            .is_err());
    }
}
