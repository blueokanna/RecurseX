//! Plain UDP DNS transport (RFC 1035, RFC 7766).

use super::io::{network_error, Deadline};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

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
        // Constructed rather than parsed. `"0.0.0.0:0".parse().unwrap()` is
        // infallible in practice but is still a parse and still a panic site,
        // and this runs once per query.
        let bind_addr = match endpoint.ip {
            IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let sock = UdpSocket::bind(bind_addr).map_err(|e| Error::io(format!("udp bind: {e}")))?;
        // Unconnected socket: recv_from reports the real source so a
        // response from an unexpected address is rejected (anti-spoofing).
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
                // Both spellings of "the read timed out": Unix and Go-style
                // pollers report `WouldBlock`, while Windows reports the socket's
                // own `WSAETIMEDOUT`. Missing the second one made a dead upstream
                // look like an I/O fault to every caller that matches on
                // `ErrorKind` — a timeout is not a broken socket, and the
                // distinction is the whole reason the kinds exist.
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
                    // Windows reports ICMP errors on connected-style UDP
                    // paths; treat as a transient failure of this attempt.
                    return Err(Error::io(format!("udp reset: {e}")));
                }
                Err(e) => return Err(Error::io(format!("udp recv: {e}"))),
            };
            if src == target {
                return Ok(crate::wire::capped(&buf, n).to_vec());
            }
            // Datagram from an unexpected source: ignore and keep reading
            // (bounded by the read timeout).
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
        // 192.0.2.0/24 is TEST-NET and not routable; on loopback it usually
        // returns an unreachable error quickly. Either way the exchange
        // must fail, not hang.
        let t = UdpTransport::default();
        let ep = Endpoint::udp("192.0.2.1".parse().unwrap());
        let r = t.exchange(b"\x00", &ep, 200);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_wrong_source() {
        // Send a query to ourselves; the response comes back from the
        // bound port, not from the target, so it must be ignored/looped
        // until timeout.
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let sock = UdpSocket::bind(bind).unwrap();
        let local = sock.local_addr().unwrap();
        // The transport binds its own socket; we can't easily point it at
        // a port that responds. This test only checks the timeout path.
        let t = UdpTransport::default();
        let ep = Endpoint::new(local.ip(), local.port(), Proto::Udp);
        let r = t.exchange(b"\x00", &ep, 100);
        // No server is listening on `local` (the transport's socket is a
        // different one), so this fails with a connect/send error or
        // timeout — either way, an error.
        assert!(r.is_err());
        let _ = sock;
    }
}
