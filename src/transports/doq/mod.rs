//! DNS over QUIC (RFC 9250): framing, session semantics, error codes, and
//! a real QUIC client transport.
//!
//! The protocol layer is implemented here — 2-octet length-prefixed
//! messages, one query per fresh bidirectional stream, the mandatory
//! session stream, and the DOQ_* error-code mapping. The QUIC transport
//! itself ([`quic`]) and the QUIC-TLS handshake ([`tls`]) are implemented
//! from the RFCs on top of courierust's public wire codecs, so the
//! default transport talks to real RFC 9250 servers (Cloudflare, AdGuard,
//! ...) out of the box — no provider wiring required.
//!
//! Advanced embeddings that want to substitute their own QUIC stack can
//! still do so through the [`DoqProvider`] / [`DoqConnection`] traits.

pub mod quic;
pub mod tls;

use alloc::string::String;
use alloc::vec::Vec;
use crate::sync::Mutex;
use crate::wire::WireBytes;
use std::time::{SystemTime, UNIX_EPOCH};

use courierust::courierust_tls::RootStore;

use crate::error::{Error, Result};
use crate::message::Message;
use crate::transport::{DnsTransport, MAX_TCP_MESSAGE};
use crate::upstream::{Endpoint, Proto};

/// RFC 9250 §7: DOQ application error codes.
pub mod error_code {
    /// No error.
    pub const NO_ERROR: u64 = 0x0;
    /// The server experienced an internal error.
    pub const INTERNAL_ERROR: u64 = 0x1;
    /// The client or server detected a protocol violation.
    pub const PROTOCOL_ERROR: u64 = 0x2;
    /// The request was cancelled (e.g. client timeout).
    pub const REQUEST_CANCELLED: u64 = 0x3;
    /// The server is experiencing excessive load.
    pub const EXCESSIVE_LOAD: u64 = 0x4;
    /// An unspecified error.
    pub const UNSPECIFIED_ERROR: u64 = 0x5;
    /// Reserved error code.
    pub const ERROR_RESERVED: u64 = 0x6;

    /// A human-readable name for a DOQ error code.
    pub fn name(code: u64) -> &'static str {
        match code {
            NO_ERROR => "DOQ_NO_ERROR",
            INTERNAL_ERROR => "DOQ_INTERNAL_ERROR",
            PROTOCOL_ERROR => "DOQ_PROTOCOL_ERROR",
            REQUEST_CANCELLED => "DOQ_REQUEST_CANCELLED",
            EXCESSIVE_LOAD => "DOQ_EXCESSIVE_LOAD",
            UNSPECIFIED_ERROR => "DOQ_UNSPECIFIED_ERROR",
            ERROR_RESERVED => "DOQ_ERROR_RESERVED",
            _ => "DOQ_UNKNOWN",
        }
    }
}

/// Frame a DNS message for DoQ: a 2-octet big-endian length prefix
/// followed by the message (RFC 9250 §4.2).
pub fn frame_query(query: &[u8]) -> Result<Vec<u8>> {
    if query.len() > MAX_TCP_MESSAGE {
        return Err(Error::transport("query too large for DoQ"));
    }
    let mut out = Vec::with_capacity(query.len() + 2);
    out.extend_from_slice(&(query.len() as u16).to_be_bytes());
    out.extend_from_slice(query);
    Ok(out)
}

/// Parse a DoQ-framed response (exactly one framed message).
pub fn deframe_response(bytes: &[u8]) -> Result<Message> {
    if bytes.len() < 2 {
        return Err(Error::wire("DoQ response shorter than length prefix"));
    }
    let len = usize::from(bytes.u16_at(0)?);
    if bytes.len() != 2 + len {
        return Err(Error::wire("DoQ response length mismatch"));
    }
    Message::parse(bytes.rest_at(2)?)
}

/// A single DoQ connection: one QUIC connection speaking RFC 9250.
pub trait DoqConnection: Send {
    /// Send a framed query on a fresh client-initiated bidirectional stream
    /// and return the framed response bytes.
    fn request(&mut self, framed_query: &[u8]) -> Result<Vec<u8>>;
    /// Gracefully close the session.
    fn close(&mut self);
}

/// Opens DoQ connections for an endpoint.
pub trait DoqProvider: Send + Sync {
    /// Establish a new DoQ session (ALPN `doq`).
    fn open(
        &self,
        endpoint: &Endpoint,
        host: Option<&str>,
        roots: &RootStore,
        verify: bool,
        now: i64,
    ) -> Result<Box<dyn DoqConnection>>;
}

/// The built-in provider: a from-scratch RFC 9000/9001/9002 client
/// (see [`quic`]) speaking ALPN `doq`.
#[derive(Debug, Clone, Copy, Default)]
pub struct BuiltinProvider;

impl DoqProvider for BuiltinProvider {
    fn open(
        &self,
        endpoint: &Endpoint,
        host: Option<&str>,
        roots: &RootStore,
        verify: bool,
        now: i64,
    ) -> Result<Box<dyn DoqConnection>> {
        let conn =
            quic::QuicConnection::connect(endpoint, host, roots.clone(), verify, now, 10_000)?;
        Ok(Box::new(BuiltinConnection {
            inner: Mutex::new(Some(conn)),
        }))
    }
}

/// A [`DoqConnection`] backed by the built-in QUIC client. A `Mutex`
/// serializes exchanges on one connection (matching the DoT/DoH
/// transports); on any transport error the connection is dropped so the
/// next request reconnects.
struct BuiltinConnection {
    inner: Mutex<Option<quic::QuicConnection>>,
}

impl DoqConnection for BuiltinConnection {
    fn request(&mut self, framed_query: &[u8]) -> Result<Vec<u8>> {
        let mut guard = self.inner.lock();
        let conn = guard
            .as_mut()
            .ok_or_else(|| Error::transport("doq connection closed"))?;
        let resp = conn.exchange_query(framed_query, 10_000);
        match resp {
            Ok(bytes) => Ok(bytes),
            Err(e) => {
                // The connection is no longer usable; drop it so the next
                // call reconnects.
                *guard = None;
                Err(e)
            }
        }
    }

    fn close(&mut self) {
        if let Some(conn) = self.inner.lock().as_mut() {
            conn.close();
        }
    }
}

/// The DoQ transport.
///
/// The default configuration uses the built-in QUIC client with the
/// certificate/verification settings supplied by the resolver (via
/// [`DoqTransport::for_host`]). A custom QUIC stack can be substituted
/// with [`DoqTransport::with_provider`].
pub struct DoqTransport {
    /// TLS server name for certificate verification and SNI.
    pub host: Option<String>,
    /// Trust roots.
    pub roots: RootStore,
    /// Whether to verify the server certificate.
    pub verify: bool,
    /// Current unix time (seconds) for certificate validity.
    pub now: i64,
    /// Optional custom QUIC provider (overrides the built-in client).
    pub provider: Option<Box<dyn DoqProvider>>,
    /// The live built-in connection (only used when `provider` is None).
    conn: Mutex<Option<quic::QuicConnection>>,
}

/// Which server this transport talks to and how it verifies it; the live
/// connection is not touched (`Debug` must never block on a lock).
impl core::fmt::Debug for DoqTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "DoqTransport(host={:?}, verify={}, roots={}, provider={})",
            self.host,
            self.verify,
            self.roots.len(),
            if self.provider.is_some() {
                "custom"
            } else {
                "builtin"
            }
        )
    }
}

impl Default for DoqTransport {
    fn default() -> Self {
        Self {
            host: None,
            roots: RootStore::new(),
            verify: true,
            now: unix_now(),
            provider: None,
            conn: Mutex::new(None),
        }
    }
}

impl DoqTransport {
    /// A transport for `hostname` (used for SNI and verification),
    /// mirroring the DoT/DoH transports.
    pub fn for_host(hostname: impl Into<String>, roots: RootStore, verify: bool, now: i64) -> Self {
        Self {
            host: Some(hostname.into()),
            roots,
            verify,
            now,
            provider: None,
            conn: Mutex::new(None),
        }
    }

    /// A transport with a custom QUIC connection provider.
    pub fn with_provider(provider: Box<dyn DoqProvider>) -> Self {
        Self {
            host: None,
            roots: RootStore::new(),
            verify: false,
            now: 0,
            provider: Some(provider),
            conn: Mutex::new(None),
        }
    }
}

/// Current Unix time in seconds.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl DnsTransport for DoqTransport {
    fn proto(&self) -> Proto {
        Proto::DoQ
    }

    fn exchange(&self, query: &[u8], endpoint: &Endpoint, timeout_ms: u64) -> Result<Vec<u8>> {
        if query.len() > MAX_TCP_MESSAGE {
            return Err(Error::transport("query too large for DoQ"));
        }
        let framed = frame_query(query)?;
        let resp = if let Some(provider) = &self.provider {
            let mut conn = provider.open(
                endpoint,
                self.host.as_deref(),
                &self.roots,
                self.verify,
                self.now,
            )?;
            let r = conn.request(&framed);
            conn.close();
            r?
        } else {
            let mut guard = self.conn.lock();
            let conn = match guard.as_mut() {
                Some(c) if c.is_open() => c,
                _ => {
                    // The caller's timeout is the bound, verbatim. It used to be
                    // floored at 10 s "because a QUIC handshake needs more than a
                    // UDP exchange", which quietly turned a 200 ms request into a
                    // ten-second stall and made every deadline above it — the
                    // engine's per-query budget included — meaningless for DoQ.
                    // A caller that wants ten seconds can ask for ten seconds.
                    let c = quic::QuicConnection::connect(
                        endpoint,
                        self.host.as_deref(),
                        self.roots.clone(),
                        self.verify,
                        self.now,
                        timeout_ms,
                    )?;
                    *guard = Some(c);
                    guard.as_mut().unwrap()
                }
            };
            match conn.exchange_query(&framed, timeout_ms) {
                Ok(bytes) => bytes,
                Err(e) => {
                    *guard = None;
                    return Err(e);
                }
            }
        };
        let _ = deframe_response(&resp)?;
        Ok(resp.rest_at(2)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::Name;
    use crate::qtype::RrType;

    #[test]
    fn framing_roundtrip() {
        let m = Message::query(7, Name::from_ascii("example.com").unwrap(), RrType::A, true);
        let bytes = m.to_bytes().unwrap();
        let framed = frame_query(&bytes).unwrap();
        assert_eq!(framed.len(), bytes.len() + 2);
        assert_eq!(&framed[..2], &(bytes.len() as u16).to_be_bytes());
        let back = deframe_response(&framed).unwrap();
        assert_eq!(back.id, 7);
    }

    #[test]
    fn deframe_rejects_bad_length() {
        let mut bytes = vec![0u8, 5, 1, 2, 3];
        // Declared 5 bytes but only 3 present.
        assert!(deframe_response(&bytes).is_err());
        bytes = vec![0u8, 0x00, 0x02, 1, 2, 3];
        // Declared 2 but 3 trailing bytes present.
        assert!(deframe_response(&bytes).is_err());
    }

    #[test]
    fn error_code_names() {
        assert_eq!(error_code::name(0), "DOQ_NO_ERROR");
        assert_eq!(error_code::name(2), "DOQ_PROTOCOL_ERROR");
        assert_eq!(error_code::name(99), "DOQ_UNKNOWN");
    }

    #[test]
    fn builtin_provider_is_not_a_noop() {
        // The default transport must carry a real QUIC stack, not a
        // "not implemented" provider. 192.0.2.1 is TEST-NET: the Initial goes
        // nowhere and nothing ever comes back, so the transport has to give up
        // by itself.
        let t = DoqTransport::default();
        let ep = Endpoint::new("192.0.2.1".parse().unwrap(), 853, Proto::DoQ);
        let started = std::time::Instant::now();
        let r = t.exchange(b"\x00", &ep, 200);
        let elapsed = started.elapsed();
        let e = r.expect_err("a blackhole DoQ endpoint must fail");
        assert_ne!(
            e.kind,
            crate::error::ErrorKind::Unsupported,
            "DoQ must use the built-in client, not report unsupported"
        );
        assert_eq!(
            e.kind,
            crate::error::ErrorKind::Timeout,
            "an unreachable peer must surface as a timeout, not as {e}"
        );
        // And the requested timeout is the bound. This assertion is the reason
        // the test exists: the transport used to floor the caller at 10 s, so a
        // 200 ms request took ten seconds. That is not a slow test, it is a
        // broken contract, and it is invisible without a clock in the test.
        assert!(
            elapsed < std::time::Duration::from_millis(1_500),
            "a 200 ms budget took {elapsed:?}"
        );
    }
}
