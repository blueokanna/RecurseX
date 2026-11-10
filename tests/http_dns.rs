#![cfg(feature = "doh")]

#[path = "support/encrypted.rs"]
mod encrypted;

use courierust::courierust_body::Body;
use courierust::courierust_http::{request::Request, response::Response};
use courierust::courierust_net::stats::Stats;
use courierust::courierust_server::{Server, ServerConfig, ServerHandle, TlsSettings};
use courierust::courierust_tls::{Identity, RootStore};
use encrypted::IO_TIMEOUT_MS as REQUEST_TIMEOUT_MS;
use recurse_x::transport::DnsTransport;
use recurse_x::upstream::{Endpoint, Proto};
use recurse_x::{Message, Name, RrType};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

const CERT: &[u8] = include_bytes!("fixtures/loopback-ip.der");
const KEY: &[u8] = include_bytes!("fixtures/loopback-ip-key.der");

#[derive(Default)]
struct ResponseGate {
    released: Mutex<bool>,
    wake: Condvar,
}

impl ResponseGate {
    fn wait(&self) {
        let released = self
            .released
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        drop(
            self.wake
                .wait_while(released, |released| !*released)
                .unwrap_or_else(|error| error.into_inner()),
        );
    }

    fn release(&self) {
        *self
            .released
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = true;
        self.wake.notify_all();
    }
}

struct Upstream {
    address: SocketAddr,
    server: Option<ServerHandle>,
    calls: Arc<AtomicUsize>,
    stats: Arc<Stats>,
    response_gate: Arc<ResponseGate>,
    _serial: MutexGuard<'static, ()>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        // Also release a blocked handler when a client assertion unwinds.
        self.response_gate.release();
        if let Some(server) = self.server.take() {
            server.stop();
            let _ = server.join();
        }
    }
}

fn upstream(http3: bool, content_type: &'static str, redirect: bool) -> Upstream {
    let serial = encrypted::serial();
    let stats = Stats::new();
    let io_timeout = encrypted::IO_TIMEOUT;
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http2: true,
            http3,
            threads: 2,
            event_workers: 1,
            read_timeout: Some(io_timeout),
            handshake_timeout: Some(io_timeout),
            idle_timeout: Some(io_timeout),
            h2_idle_timeout: Some(io_timeout),
            tls: Some(TlsSettings {
                identity: Identity::from_der(vec![CERT.to_vec()], KEY.to_vec()).unwrap(),
                alpn: if http3 {
                    vec![b"h3".to_vec()]
                } else {
                    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
                },
                ..Default::default()
            }),
            stats: Some(stats.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    let address = server.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let response_gate = Arc::new(ResponseGate::default());
    let handler_gate = response_gate.clone();
    let handle = server
        .serve_background(move |request: Request<Body>| {
            assert_eq!(
                request.headers.get("content-type").unwrap().as_bytes(),
                b"application/dns-message"
            );
            assert_eq!(
                request.headers.get("accept").unwrap().as_bytes(),
                b"application/dns-message"
            );
            let bytes = request.body.collect().unwrap();
            let mut message = Message::parse(&bytes).unwrap();
            observed.fetch_add(1, Ordering::Relaxed);
            if request.uri.as_str() == "/slow" {
                handler_gate.wait();
            }
            if redirect {
                return Response::<Body>::with_status(
                    courierust::courierust_http::StatusCode::TEMPORARY_REDIRECT,
                )
                .header("location", "http://127.0.0.1:1/leak");
            }
            message.flags.qr = true;
            let mut response =
                Response::<Body>::with_status(courierust::courierust_http::StatusCode::OK)
                    .header("content-type", content_type);
            response.body = Body::from(message.to_bytes().unwrap());
            response
        })
        .unwrap();
    Upstream {
        address,
        server: Some(handle),
        calls,
        stats,
        response_gate,
        _serial: serial,
    }
}

fn transport(http3: bool, trust: bool, now: i64) -> Box<dyn DnsTransport> {
    let mut roots = RootStore::new();
    if trust {
        roots.add_der(CERT.to_vec());
    }
    #[cfg(feature = "doh3")]
    if http3 {
        return Box::new(recurse_x::transports::doh3::Doh3Transport::for_host(
            "127.0.0.1",
            roots,
            true,
            now,
        ));
    }
    assert!(!http3);
    Box::new(recurse_x::transports::doh::DohTransport::for_host(
        "127.0.0.1",
        roots,
        true,
        now,
    ))
}

fn query() -> Vec<u8> {
    Message::query(
        42,
        Name::from_ascii("test.example").unwrap(),
        RrType::A,
        true,
    )
    .to_bytes()
    .unwrap()
}

fn roundtrip(http3: bool) {
    let upstream = upstream(http3, "application/dns-message", false);
    let transport = transport(http3, true, 1_800_000_000);
    let endpoint = Endpoint::new(
        upstream.address.ip(),
        upstream.address.port(),
        if http3 { Proto::DoH3 } else { Proto::DoH },
    );
    for _ in 0..2 {
        let response = transport
            .exchange(&query(), &endpoint, REQUEST_TIMEOUT_MS)
            .unwrap();
        assert!(Message::parse(&response).unwrap().flags.qr);
    }
    assert_eq!(upstream.calls.load(Ordering::Relaxed), 2);
    let stats = upstream.stats.snapshot();
    assert_eq!(
        if http3 {
            stats.h3_connections
        } else {
            stats.h2_connections
        },
        1,
        "existing courierust connection pool must be reused"
    );
}

#[test]
fn doh_uses_configured_ip_and_reuses_http2() {
    roundtrip(false);
}

fn network_change_reopens_connection(http3: bool) {
    let upstream = upstream(http3, "application/dns-message", false);
    let transport = transport(http3, true, 1_800_000_000);
    let endpoint = Endpoint::new(
        upstream.address.ip(),
        upstream.address.port(),
        if http3 { Proto::DoH3 } else { Proto::DoH },
    );
    transport
        .exchange(&query(), &endpoint, REQUEST_TIMEOUT_MS)
        .unwrap();
    courierust::courierust_net::outbound::network_changed();
    for _ in 0..2 {
        transport
            .exchange(&query(), &endpoint, REQUEST_TIMEOUT_MS)
            .unwrap();
    }
    let stats = upstream.stats.snapshot();
    assert_eq!(upstream.calls.load(Ordering::Relaxed), 3);
    assert_eq!(
        if http3 {
            stats.h3_connections
        } else {
            stats.h2_connections
        },
        2
    );
}

#[test]
fn standalone_doh_invalidates_its_pool_on_network_change() {
    network_change_reopens_connection(false);
}

#[cfg(feature = "doh3")]
#[test]
fn standalone_doh3_invalidates_its_pool_on_network_change() {
    network_change_reopens_connection(true);
}

#[cfg(feature = "doh3")]
#[test]
fn doh3_uses_configured_ip_and_reuses_quic() {
    roundtrip(true);
}

#[test]
fn doh_rejects_redirects_and_invalid_media_type() {
    for (media_type, redirect) in [("text/plain", false), ("application/dns-message", true)] {
        let upstream = upstream(false, media_type, redirect);
        let endpoint = Endpoint::new(upstream.address.ip(), upstream.address.port(), Proto::DoH);
        assert!(transport(false, true, 1_800_000_000)
            .exchange(&query(), &endpoint, REQUEST_TIMEOUT_MS)
            .is_err());
        assert_eq!(upstream.calls.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn doh_certificate_failure_precedes_dns_payload() {
    certificate_failure(false);
}

#[cfg(feature = "doh3")]
#[test]
fn doh3_certificate_failure_precedes_dns_payload() {
    certificate_failure(true);
}

fn certificate_failure(http3: bool) {
    let upstream = upstream(http3, "application/dns-message", false);
    let endpoint = Endpoint::new(
        upstream.address.ip(),
        upstream.address.port(),
        if http3 { Proto::DoH3 } else { Proto::DoH },
    );
    for (trusted, time) in [(false, 1_800_000_000), (true, 2_200_000_000)] {
        let error = transport(http3, trusted, time)
            .exchange(&query(), &endpoint, REQUEST_TIMEOUT_MS)
            .unwrap_err();
        assert_ne!(error.kind, recurse_x::ErrorKind::Timeout, "{error:?}");
    }
    assert_eq!(upstream.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn changing_validation_time_cannot_reuse_an_old_client() {
    let upstream = upstream(false, "application/dns-message", false);
    let mut roots = RootStore::new();
    roots.add_der(CERT.to_vec());
    let mut transport =
        recurse_x::transports::doh::DohTransport::for_host("127.0.0.1", roots, true, 1_800_000_000);
    let endpoint = Endpoint::new(upstream.address.ip(), upstream.address.port(), Proto::DoH);
    transport
        .exchange(&query(), &endpoint, REQUEST_TIMEOUT_MS)
        .unwrap();
    transport.now = 2_200_000_000;
    let error = transport
        .exchange(&query(), &endpoint, REQUEST_TIMEOUT_MS)
        .unwrap_err();
    assert_ne!(error.kind, recurse_x::ErrorKind::Timeout, "{error:?}");
    assert_eq!(upstream.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn hostname_routing_mismatch_is_rejected_before_connecting() {
    let endpoint = Endpoint::new("127.0.0.1".parse().unwrap(), 1, Proto::DoH);
    let transport = recurse_x::transports::doh::DohTransport::for_host(
        "unresolvable.invalid",
        RootStore::new(),
        false,
        0,
    );
    assert_eq!(
        transport
            .exchange(&query(), &endpoint, 500)
            .unwrap_err()
            .kind,
        recurse_x::ErrorKind::Config
    );
}

#[test]
fn http_timeout_is_reported_as_timeout_for_failure_fallback() {
    let upstream = upstream(false, "application/dns-message", false);
    let mut roots = RootStore::new();
    roots.add_der(CERT.to_vec());
    let mut transport =
        recurse_x::transports::doh::DohTransport::for_host("127.0.0.1", roots, true, 1_800_000_000);
    transport.path = "/slow".into();
    let endpoint = Endpoint::new(upstream.address.ip(), upstream.address.port(), Proto::DoH);
    let started = std::time::Instant::now();
    let error = transport.exchange(&query(), &endpoint, 2_000).unwrap_err();
    assert_eq!(
        error.kind,
        recurse_x::ErrorKind::Timeout,
        "{error:?}; elapsed={:?}",
        started.elapsed()
    );
    assert_eq!(
        upstream.calls.load(Ordering::Relaxed),
        1,
        "timeout must occur after the server receives DNS, not during TLS setup"
    );
}
