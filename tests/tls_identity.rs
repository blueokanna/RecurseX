#![cfg(feature = "dot")]

use courierust::courierust_tls::{Identity, RootStore, ServerConfig, TlsAcceptor};
use recurse_x::transport::DnsTransport;
use recurse_x::transports::dot::DotTransport;
use recurse_x::upstream::{Endpoint, Proto};
use std::net::TcpListener;
use std::time::Duration;

// Generated specifically for these tests. This key is public test material.
const CERT: &[u8] = include_bytes!("fixtures/localhost.der");
const KEY: &[u8] = include_bytes!("fixtures/localhost-key.der");

fn exchange(host: &str, trust: bool, now: i64) -> (bool, bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let acceptor = TlsAcceptor::new(ServerConfig {
            identity: Identity::from_der(vec![CERT.to_vec()], KEY.to_vec()).unwrap(),
            alpn: vec![b"dot".to_vec()],
            ..ServerConfig::default()
        });
        let Ok(mut tls) = acceptor.accept(&stream, &stream) else {
            return false;
        };
        let Ok(data) = tls.read_record() else {
            return false;
        };
        if data.is_empty() {
            return false;
        }
        tls.write_all(&[0, 2, 12, 34]).unwrap();
        true
    });
    let mut roots = RootStore::new();
    if trust {
        roots.add_der(CERT.to_vec());
    }
    let transport = DotTransport::for_host(host, roots, true, now);
    let result = transport.exchange(
        &[12, 34],
        &Endpoint::new(addr.ip(), addr.port(), Proto::Tls),
        2000,
    );
    (result.is_ok(), server.join().unwrap())
}

#[test]
fn trusted_identity_can_exchange_dns() {
    assert_eq!(exchange("localhost", true, 1_800_000_000), (true, true));
}

#[test]
fn live_certificate_clock_is_selected_by_zero() {
    assert_eq!(exchange("localhost", true, 0), (true, true));
}

#[test]
fn wrong_hostname_never_sends_dns() {
    assert_eq!(
        exchange("wrong.example", true, 1_800_000_000),
        (false, false)
    );
}

#[test]
fn untrusted_certificate_never_sends_dns() {
    assert_eq!(exchange("localhost", false, 1_800_000_000), (false, false));
}

#[test]
fn expired_certificate_never_sends_dns() {
    assert_eq!(exchange("localhost", true, 2_200_000_000), (false, false));
}
