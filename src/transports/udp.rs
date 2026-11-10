//! Plain UDP DNS transport (RFC 1035, RFC 7766).

use super::io::{network_error, Deadline};
#[cfg(test)]
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error::{Error, Result};
use crate::transport::{DnsTransport, MAX_UDP_PAYLOAD};
use crate::upstream::{Endpoint, Proto};

/// The UDP transport.
#[derive(Clone, Copy, Debug, Default)]
pub struct UdpTransport {
    /// Receive buffer size (defaults to [`MAX_UDP_PAYLOAD`]).
    pub receive_buffer: usize,
}

impl DnsTransport for UdpTransport {
    fn proto(&self) -> Proto {
        Proto::Udp
    }

    fn exchange(&self, query: &[u8], endpoint: &Endpoint, timeout_ms: u64) -> Result<Vec<u8>> {
        let deadline = Deadline::after(timeout_ms)?;
        let bind_addr = match endpoint.ip {
            IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let sock = courierust::courierust_net::outbound::udp_bind(
            bind_addr,
            SocketAddr::new(endpoint.ip, endpoint.port),
        )
        .map_err(|e| Error::io(format!("udp bind: {e}")))?;
        sock.set_read_timeout(Some(
            deadline
                .remaining()
                .map_err(|e| network_error("UDP deadline", e))?,
        ))
        .map_err(|e| Error::io(format!("udp timeout: {e}")))?;
        let target = SocketAddr::new(endpoint.ip, endpoint.port);
        sock.send_to(query, target)
            .map_err(|e| Error::io(format!("udp send: {e}")))?;

        let mut buf = vec![0u8; self.receive_buffer.clamp(MAX_UDP_PAYLOAD, 65_535)];
        loop {
            sock.set_read_timeout(Some(
                deadline
                    .remaining()
                    .map_err(|e| network_error("UDP deadline", e))?,
            ))
            .map_err(|e| network_error("UDP timeout", e))?;
            let (n, src) = match sock.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(Error::new(
                        crate::error::ErrorKind::Timeout,
                        format!("udp timeout waiting for {}", endpoint.addr_str()),
                    ));
                }
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                    return Err(Error::io(format!("udp reset: {e}")));
                }
                Err(e) => return Err(Error::io(format!("udp recv: {e}"))),
            };
            if src == target {
                return Ok(crate::wire::capped(&buf, n).to_vec());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_source_traffic_cannot_reset_the_timeout() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = upstream.local_addr().unwrap();
        upstream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let stopped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = stopped.clone();
        let server = std::thread::spawn(move || {
            let (_, peer) = upstream.recv_from(&mut [0; 512]).unwrap();
            let wrong_source = UdpSocket::bind("127.0.0.1:0").unwrap();
            for _ in 0..100 {
                if flag.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let _ = wrong_source.send_to(&[0; 12], peer);
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        });
        let start = std::time::Instant::now();
        let result = UdpTransport::default().exchange(
            &[0; 12],
            &Endpoint::new(address.ip(), address.port(), Proto::Udp),
            80,
        );
        let elapsed = start.elapsed();
        stopped.store(true, std::sync::atomic::Ordering::Relaxed);
        server.join().unwrap();
        assert_eq!(result.unwrap_err().kind, crate::error::ErrorKind::Timeout);
        assert!(elapsed < std::time::Duration::from_millis(500));
    }

    #[test]
    fn exchange_times_out_on_dead_endpoint() {
        let t = UdpTransport::default();
        let ep = Endpoint::udp("192.0.2.1".parse().unwrap());
        let r = t.exchange(b"\x00", &ep, 200);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_wrong_source() {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let sock = UdpSocket::bind(bind).unwrap();
        let local = sock.local_addr().unwrap();
        let t = UdpTransport::default();
        let ep = Endpoint::new(local.ip(), local.port(), Proto::Udp);
        let r = t.exchange(b"\x00", &ep, 100);
        assert!(r.is_err());
        let _ = sock;
    }
}
