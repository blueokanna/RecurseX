//! DNS over QUIC (RFC 9250): framing, session semantics, error codes, and
//! a real QUIC client transport.
//!
//! The protocol layer is implemented here — 2-octet length-prefixed
//! messages, one query per fresh client-initiated bidirectional stream,
//! zero wire IDs, and the DOQ_* error-code mapping. The QUIC transport
//! itself ([`quic`]) and the QUIC-TLS handshake ([`tls`]) are implemented
//! from the RFCs on top of courierust's public wire codecs, so the
//! default transport needs no provider wiring. It remains experimental:
//! public-server interoperability and full congestion control are not established.
//!
//! Advanced embeddings that want to substitute their own QUIC stack can
//! still do so through the [`DoqProvider`] / [`DoqConnection`] traits.

pub mod quic;
pub mod tls;

use super::io::{lock_until, Deadline};
use crate::sync::Mutex;
use crate::wire::WireBytes;
use alloc::string::String;
use alloc::vec::Vec;

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
    pub const ERROR_RESERVED: u64 = 0xd098ea5e;

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
    /// Execute within the supplied remaining budget. Implementations must bound
    /// all blocking I/O. Legacy providers fail closed until they implement it.
    fn request_with_timeout(&mut self, _framed_query: &[u8], _timeout_ms: u64) -> Result<Vec<u8>> {
        Err(Error::new(
            crate::error::ErrorKind::Unsupported,
            "DoQ provider does not implement request deadlines",
        ))
    }
    /// Gracefully close the session. This must not block.
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

    /// Open within the supplied remaining budget; DNS transports never call
    /// the unbounded legacy method as a fallback.
    #[allow(clippy::too_many_arguments)]
    fn open_with_timeout(
        &self,
        _endpoint: &Endpoint,
        _host: Option<&str>,
        _roots: &RootStore,
        _verify: bool,
        _now: i64,
        _timeout_ms: u64,
    ) -> Result<Box<dyn DoqConnection>> {
        Err(Error::new(
            crate::error::ErrorKind::Unsupported,
            "DoQ provider does not implement connection deadlines",
        ))
    }
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
        self.open_with_timeout(endpoint, host, roots, verify, now, 10_000)
    }

    fn open_with_timeout(
        &self,
        endpoint: &Endpoint,
        host: Option<&str>,
        roots: &RootStore,
        verify: bool,
        now: i64,
        timeout_ms: u64,
    ) -> Result<Box<dyn DoqConnection>> {
        let conn =
            quic::QuicConnection::connect(endpoint, host, roots.clone(), verify, now, timeout_ms)?;
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
        self.request_with_timeout(framed_query, 10_000)
    }

    fn request_with_timeout(&mut self, framed_query: &[u8], timeout_ms: u64) -> Result<Vec<u8>> {
        let mut guard = self.inner.lock();
        let conn = guard
            .as_mut()
            .ok_or_else(|| Error::transport("doq connection closed"))?;
        let resp = conn.exchange_query(framed_query, timeout_ms);
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
    conn: Mutex<Option<CachedConnection>>,
}

struct CachedConnection {
    identity: ConnectionIdentity,
    connection: quic::QuicConnection,
}

#[derive(Clone)]
struct ConnectionIdentity {
    endpoint: Endpoint,
    host: Option<String>,
    roots: RootStore,
    verify: bool,
    now: i64,
    generation: u64,
}
impl ConnectionIdentity {
    fn matches(&self, other: &Self) -> bool {
        self.endpoint == other.endpoint
            && self.host == other.host
            && self.verify == other.verify
            && self.now == other.now
            && self.generation == other.generation
            && super::io::same_roots(&self.roots, &other.roots)
    }
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
            now: 0,
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
            verify: true,
            now: 0,
            provider: Some(provider),
            conn: Mutex::new(None),
        }
    }
}

impl DnsTransport for DoqTransport {
    fn proto(&self) -> Proto {
        Proto::DoQ
    }

    fn exchange(&self, query: &[u8], endpoint: &Endpoint, timeout_ms: u64) -> Result<Vec<u8>> {
        let deadline = Deadline::after(timeout_ms)?;
        let now = super::io::certificate_time(self.now)?;
        if query.len() > MAX_TCP_MESSAGE {
            return Err(Error::transport("query too large for DoQ"));
        }
        let mut message = Message::parse(query)?;
        if message.flags.qr
            || message.questions.len() != 1
            || message.flags.opcode != crate::qtype::Opcode::QUERY
        {
            return Err(Error::wire("DoQ requires a DNS query with one question"));
        }
        if self.verify
            && (self.roots.is_empty() || self.host.as_deref().map_or(true, str::is_empty))
        {
            return Err(Error::config(
                "verified DoQ requires trust roots and a TLS identity",
            ));
        }
        let original_id = message.id;
        message.id = 0;
        if let Some(edns) = &mut message.edns {
            edns.options
                .retain(|option| option.code() != crate::edns::opt::KEEPALIVE);
        }
        let framed = frame_query(&message.to_bytes()?)?;
        let mut response = if let Some(provider) = &self.provider {
            let mut conn = provider.open_with_timeout(
                endpoint,
                self.host.as_deref(),
                &self.roots,
                self.verify,
                now,
                deadline.remaining_ms()?,
            )?;
            let result = (|| {
                let bytes = conn.request_with_timeout(&framed, deadline.remaining_ms()?)?;
                deadline.remaining_ms()?;
                validate_response(&bytes, &message)
            })();
            conn.close();
            result?
        } else {
            let identity = ConnectionIdentity {
                endpoint: *endpoint,
                host: self.host.clone(),
                roots: self.roots.clone(),
                verify: self.verify,
                now,
                generation: courierust::courierust_net::outbound::generation(),
            };
            let mut guard = lock_until(&self.conn, deadline)?;
            if !guard.as_ref().is_some_and(|cached| {
                cached.connection.is_open() && cached.identity.matches(&identity)
            }) {
                // Drop the old route or identity before attempting a replacement.
                *guard = None;
                let connection = quic::QuicConnection::connect(
                    endpoint,
                    self.host.as_deref(),
                    self.roots.clone(),
                    self.verify,
                    now,
                    deadline.remaining_ms()?,
                )?;
                *guard = Some(CachedConnection {
                    identity,
                    connection,
                });
            }
            let result = (|| {
                let cached = guard
                    .as_mut()
                    .ok_or_else(|| Error::internal("missing DoQ connection"))?;
                let bytes = cached
                    .connection
                    .exchange_query(&framed, deadline.remaining_ms()?)?;
                deadline.remaining_ms()?;
                validate_response(&bytes, &message)
            })();
            match result {
                Ok(response) => response,
                Err(error) => {
                    *guard = None;
                    return Err(error);
                }
            }
        };
        response.id = original_id;
        response.to_bytes()
    }
}

fn validate_response(bytes: &[u8], query: &Message) -> Result<Message> {
    let response = deframe_response(bytes)?;
    if !crate::query::response_matches_query(query, &response) || response.flags.tc {
        return Err(Error::transport(
            "DoQ response has an invalid ID, question or flags",
        ));
    }
    if response.edns.as_ref().is_some_and(|edns| {
        edns.options
            .iter()
            .any(|option| option.code() == crate::edns::opt::KEEPALIVE)
    }) {
        return Err(Error::transport(
            "DoQ response contains forbidden TCP keepalive",
        ));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::Name;
    use crate::qtype::RrType;

    struct EchoProvider {
        bad_id: bool,
        closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }
    struct EchoConnection {
        bad_id: bool,
        closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }
    impl DoqProvider for EchoProvider {
        fn open(
            &self,
            _: &Endpoint,
            _: Option<&str>,
            _: &RootStore,
            _: bool,
            _: i64,
        ) -> Result<Box<dyn DoqConnection>> {
            panic!("transport called unbounded provider open")
        }
        fn open_with_timeout(
            &self,
            _: &Endpoint,
            _: Option<&str>,
            _: &RootStore,
            _: bool,
            _: i64,
            timeout: u64,
        ) -> Result<Box<dyn DoqConnection>> {
            assert!((1..=500).contains(&timeout));
            Ok(Box::new(EchoConnection {
                bad_id: self.bad_id,
                closed: self.closed.clone(),
            }))
        }
    }
    impl DoqConnection for EchoConnection {
        fn request(&mut self, _: &[u8]) -> Result<Vec<u8>> {
            panic!("transport called unbounded provider request")
        }
        fn request_with_timeout(&mut self, bytes: &[u8], timeout: u64) -> Result<Vec<u8>> {
            assert!((1..=500).contains(&timeout));
            let mut message = deframe_response(bytes)?;
            assert_eq!(message.id, 0);
            assert!(message
                .edns
                .as_ref()
                .unwrap()
                .options
                .iter()
                .all(|option| option.code() != crate::edns::opt::KEEPALIVE));
            message.flags.qr = true;
            if self.bad_id {
                message.id = 7;
            }
            frame_query(&message.to_bytes()?)
        }
        fn close(&mut self) {
            self.closed
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    #[test]
    fn doq_wire_id_is_zero_and_client_id_is_restored_only_after_validation() {
        for bad_id in [false, true] {
            let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let mut transport = DoqTransport::with_provider(Box::new(EchoProvider {
                bad_id,
                closed: closed.clone(),
            }));
            transport.verify = false; // No TLS in this protocol-boundary fixture.
            let mut query = Message::query(
                123,
                Name::from_ascii("example.com").unwrap(),
                RrType::A,
                true,
            );
            let mut edns = crate::edns::Edns::new(1232);
            edns.options
                .push(crate::edns::EdnsOption::TcpKeepalive(None));
            query.edns = Some(edns);
            let result = transport.exchange(
                &query.to_bytes().unwrap(),
                &Endpoint::new("127.0.0.1".parse().unwrap(), 853, Proto::DoQ),
                500,
            );
            if bad_id {
                assert!(result.is_err());
            } else {
                assert_eq!(Message::parse(&result.unwrap()).unwrap().id, 123);
            }
            assert!(closed.load(std::sync::atomic::Ordering::Acquire));
        }
    }

    #[test]
    fn connection_identity_includes_route_certificate_settings_and_egress_generation() {
        let identity = ConnectionIdentity {
            endpoint: Endpoint::new("127.0.0.1".parse().unwrap(), 853, Proto::DoQ),
            host: Some("localhost".into()),
            roots: RootStore::new(),
            verify: true,
            now: 1,
            generation: 0,
        };
        for field in 0..6 {
            let mut changed = identity.clone();
            match field {
                0 => changed.endpoint.port += 1,
                1 => changed.host = Some("different.example".into()),
                2 => changed.roots.add_der(vec![1]),
                3 => changed.verify = false,
                4 => changed.now += 1,
                _ => changed.generation += 1,
            }
            assert!(!identity.matches(&changed));
        }
        assert!(identity.matches(&identity.clone()));
        assert_eq!(DoqTransport::default().now, 0);
    }

    #[test]
    fn waiting_for_a_busy_doq_connection_consumes_the_callers_deadline() {
        let transport = DoqTransport::for_host("localhost", RootStore::new(), false, 0);
        let _held = transport.conn.lock();
        let query = Message::query(1, Name::from_ascii("example.com").unwrap(), RrType::A, true)
            .to_bytes()
            .unwrap();
        let started = std::time::Instant::now();
        let error = transport
            .exchange(
                &query,
                &Endpoint::new("127.0.0.1".parse().unwrap(), 853, Proto::DoQ),
                20,
            )
            .unwrap_err();
        assert_eq!(error.kind, crate::error::ErrorKind::Timeout);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

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
        let t = DoqTransport {
            verify: false,
            ..DoqTransport::default()
        };
        let ep = Endpoint::new("192.0.2.1".parse().unwrap(), 853, Proto::DoQ);
        let started = std::time::Instant::now();
        let query = Message::query(7, Name::from_ascii("example.com").unwrap(), RrType::A, true)
            .to_bytes()
            .unwrap();
        let r = t.exchange(&query, &ep, 200);
        let elapsed = started.elapsed();
        let e = r.expect_err("a blackhole DoQ endpoint must fail");
        // Which *kind* of failure depends on the route's temper, and both are
        // right: a network that rejects TEST-NET answers `send_to` with
        // `ENETUNREACH` and the failure is `Io`, while a network that swallows
        // the datagram lets the handshake run into its deadline and the failure
        // is `Timeout`. Asserting one of them would be asserting on the
        // runner's routing table. What must never happen is `Unsupported`, which
        // would mean the built-in client is missing — the thing this test is
        // actually about.
        assert!(
            matches!(
                e.kind,
                crate::error::ErrorKind::Timeout | crate::error::ErrorKind::Io
            ),
            "an unreachable peer must fail as a timeout or an I/O error, not as {e}"
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
