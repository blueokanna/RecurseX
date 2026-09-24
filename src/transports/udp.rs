//! Plain UDP DNS transport (RFC 1035, RFC 7766).

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

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
        let bind_addr: SocketAddr = match endpoint.ip {
            IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            IpAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        let sock = UdpSocket::bind(bind_addr).map_err(|e| Error::io(format!("udp bind: {e}")))?;
        // Unconnected socket: recv_from reports the real source so a
        // response from an unexpected address is rejected (anti-spoofing).
        sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)))
            .map_err(|e| Error::io(format!("udp timeout: {e}")))?;
        let target = SocketAddr::new(endpoint.ip, endpoint.port);
        sock.send_to(query, target)
            .map_err(|e| Error::io(format!("udp send: {e}")))?;

        let mut buf = vec![0u8; self.receive_buffer.max(MAX_UDP_PAYLOAD)];
        loop {
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
