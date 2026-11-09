#![cfg(feature = "dot")]

#[path = "support/encrypted.rs"]
mod encrypted;

use courierust::courierust_io::Read;
use courierust::courierust_tls::{Identity, RootStore, ServerConfig, TlsAcceptor};
use recurse_x::transport::DnsTransport;
use recurse_x::transports::dot::DotTransport;
use recurse_x::upstream::{Endpoint, Proto};
use recurse_x::{ErrorKind, Message, Name, RrType};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// Generated specifically for these tests. This key is public test material.
const CERT: &[u8] = include_bytes!("fixtures/localhost.der");
const KEY: &[u8] = include_bytes!("fixtures/localhost-key.der");

#[derive(Debug)]
struct Exchange {
    client: recurse_x::Result<Vec<u8>>,
    server: Result<(), String>,
    application_bytes: usize,
}

fn query() -> Message {
    Message::query(
        42,
        Name::from_ascii("test.example").unwrap(),
        RrType::A,
        true,
    )
}

fn accept(listener: &TcpListener) -> Result<TcpStream, String> {
    let deadline = Instant::now() + encrypted::IO_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("server accept deadline exhausted".into());
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(format!("server accept: {error}")),
        }
    }
}

fn read_exact(
    reader: &mut impl Read,
    mut bytes: &mut [u8],
    received: &AtomicUsize,
) -> Result<(), String> {
    while !bytes.is_empty() {
        let count = reader
            .read(bytes)
            .map_err(|error| format!("server read: {error}"))?;
        if count == 0 {
            return Err("server received EOF before a complete DNS frame".into());
        }
        // Count even a partial length prefix: certificate rejection must
        // precede every application byte, not just complete DNS messages.
        received.fetch_add(count, Ordering::Relaxed);
        bytes = &mut bytes[count..];
    }
    Ok(())
}

fn serve(listener: TcpListener, received: Arc<AtomicUsize>) -> Result<(), String> {
    let stream = accept(&listener)?;
    stream
        .set_nonblocking(false)
        .map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(encrypted::IO_TIMEOUT))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(encrypted::IO_TIMEOUT))
        .map_err(|error| error.to_string())?;
    let acceptor = TlsAcceptor::new(ServerConfig {
        identity: Identity::from_der(vec![CERT.to_vec()], KEY.to_vec())
            .map_err(|error| format!("server identity: {error}"))?,
        alpn: vec![b"dot".to_vec()],
        ..ServerConfig::default()
    });
    let mut tls = acceptor
        .accept(&stream, &stream)
        .map_err(|error| format!("server handshake: {error}"))?;
    let mut prefix = [0; 2];
    read_exact(&mut tls, &mut prefix, &received)?;
    let expected = query().to_bytes().unwrap();
    let length = usize::from(u16::from_be_bytes(prefix));
    if length != expected.len() {
        return Err(format!(
            "server received DNS length {length}, expected {}",
            expected.len()
        ));
    }
    let mut body = vec![0; length];
    read_exact(&mut tls, &mut body, &received)?;
    if body != expected {
        return Err(format!("server received an unexpected DNS query: {body:?}"));
    }
    let mut response =
        Message::parse(&body).map_err(|error| format!("server DNS parse: {error}"))?;
    response.flags.qr = true;
    let response = response.to_bytes().unwrap();
    let prefix = (response.len() as u16).to_be_bytes();
    // A DNS frame may span TLS records. Split both the length and body so
    // the successful exchange also checks the transport's framing loop.
    for fragment in [&prefix[..1], &prefix[1..], &response[..7], &response[7..]] {
        tls.write_all(fragment)
            .map_err(|error| format!("server write: {error}"))?;
    }
    Ok(())
}

fn exchange(host: &str, trust: bool, now: i64) -> Exchange {
    let _serial = encrypted::serial();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let received = Arc::new(AtomicUsize::new(0));
    let observed = received.clone();
    let server = std::thread::spawn(move || serve(listener, observed));
    let mut roots = RootStore::new();
    if trust {
        roots.add_der(CERT.to_vec());
    }
    let transport = DotTransport::for_host(host, roots, true, now);
    let client = transport.exchange(
        &query().to_bytes().unwrap(),
        &Endpoint::new(addr.ip(), addr.port(), Proto::Tls),
        encrypted::IO_TIMEOUT_MS,
    );
    let server = server.join().expect("TLS fixture server panicked");
    Exchange {
        client,
        server,
        application_bytes: received.load(Ordering::Relaxed),
    }
}

fn assert_success(now: i64) {
    let result = exchange("localhost", true, now);
    let mut response = query();
    response.flags.qr = true;
    assert_eq!(result.server, Ok(()), "{result:?}");
    assert_eq!(
        result.client,
        Ok(response.to_bytes().unwrap()),
        "{result:?}"
    );
    assert_eq!(
        result.application_bytes,
        query().to_bytes().unwrap().len() + 2
    );
}

fn assert_certificate_rejected(host: &str, trust: bool, now: i64, reason: &str) {
    let result = exchange(host, trust, now);
    let Err(error) = &result.client else {
        panic!("invalid certificate was accepted: {result:?}");
    };
    assert_eq!(error.kind, ErrorKind::Transport, "{result:?}");
    assert!(
        error.msg.contains("TLS certificate error:") && error.msg.contains(reason),
        "{result:?}"
    );
    assert_eq!(result.application_bytes, 0, "{result:?}");
    assert!(result.server.is_err(), "{result:?}");
}

#[test]
fn trusted_identity_can_exchange_dns() {
    assert_success(1_800_000_000);
}

#[test]
fn live_certificate_clock_is_selected_by_zero() {
    assert_success(0);
}

#[test]
fn wrong_hostname_never_sends_dns() {
    assert_certificate_rejected("wrong.example", true, 1_800_000_000, "hostname mismatch");
}

#[test]
fn untrusted_certificate_never_sends_dns() {
    assert_certificate_rejected("localhost", false, 1_800_000_000, "no trusted root found");
}

#[test]
fn expired_certificate_never_sends_dns() {
    assert_certificate_rejected("localhost", true, 2_200_000_000, "outside validity window");
}
