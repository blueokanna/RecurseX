//! One isolated process: Courierust's socket factory can only be installed once.
#![cfg(feature = "std")]

use recurse_x::transport::DnsTransport;
use recurse_x::upstream::{Endpoint, Proto};
use recurse_x::{Message, Name, RrType};
use std::io;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static TCP: AtomicUsize = AtomicUsize::new(0);
static UDP: AtomicUsize = AtomicUsize::new(0);

fn deny_tcp(_: &SocketAddr, timeout: Option<Duration>) -> io::Result<TcpStream> {
    assert!(timeout.is_some_and(|timeout| !timeout.is_zero()));
    TCP.fetch_add(1, Ordering::Relaxed);
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "test egress denial",
    ))
}

fn deny_udp(_: SocketAddr, _: SocketAddr) -> io::Result<UdpSocket> {
    UDP.fetch_add(1, Ordering::Relaxed);
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "test egress denial",
    ))
}

#[test]
fn every_transport_honors_courierust_factory_denial_without_os_fallback() {
    use courierust::courierust_net::outbound::{self, SocketFactory};
    let generation = outbound::generation();
    outbound::install(SocketFactory {
        tcp: deny_tcp,
        udp: deny_udp,
    })
    .unwrap();
    assert!(outbound::generation() > generation);
    let query = Message::query(
        1,
        Name::from_ascii("egress.example").unwrap(),
        RrType::A,
        true,
    )
    .to_bytes()
    .unwrap();
    let mut transports: Vec<(Box<dyn DnsTransport>, Proto)> = vec![
        (
            Box::<recurse_x::transports::udp::UdpTransport>::default(),
            Proto::Udp,
        ),
        (
            Box::<recurse_x::transports::tcp::TcpTransport>::default(),
            Proto::Tcp,
        ),
    ];
    #[cfg(feature = "dot")]
    transports.push((
        Box::new(recurse_x::transports::dot::DotTransport::for_host(
            "127.0.0.1",
            courierust::courierust_tls::RootStore::new(),
            false,
            0,
        )),
        Proto::Tls,
    ));
    #[cfg(feature = "doh")]
    transports.push((
        Box::new(recurse_x::transports::doh::DohTransport::for_host(
            "127.0.0.1",
            courierust::courierust_tls::RootStore::new(),
            false,
            0,
        )),
        Proto::DoH,
    ));
    #[cfg(feature = "doh3")]
    transports.push((
        Box::new(recurse_x::transports::doh3::Doh3Transport::for_host(
            "127.0.0.1",
            courierust::courierust_tls::RootStore::new(),
            false,
            0,
        )),
        Proto::DoH3,
    ));
    #[cfg(feature = "doq")]
    transports.push((
        Box::new(recurse_x::transports::doq::DoqTransport::for_host(
            "127.0.0.1",
            courierust::courierust_tls::RootStore::new(),
            false,
            0,
        )),
        Proto::DoQ,
    ));
    for (transport, proto) in transports.drain(..) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let datagrams = UdpSocket::bind(address).unwrap();
        datagrams.set_nonblocking(true).unwrap();
        let before = TCP.load(Ordering::Relaxed) + UDP.load(Ordering::Relaxed);
        assert!(transport
            .exchange(
                &query,
                &Endpoint::new(address.ip(), address.port(), proto),
                1000
            )
            .is_err());
        assert!(
            TCP.load(Ordering::Relaxed) + UDP.load(Ordering::Relaxed) > before,
            "{proto:?} bypassed the factory"
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            datagrams.recv_from(&mut [0; 2048]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
