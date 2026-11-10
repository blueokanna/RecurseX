//! Reserve one loopback endpoint for both DNS wire transports.

use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};

const MAX_BIND_ATTEMPTS: usize = 32;

pub(crate) fn bind_dns_pair() -> io::Result<(TcpListener, UdpSocket)> {
    bind_with_udp(UdpSocket::bind)
}

fn bind_with_udp(
    mut bind_udp: impl FnMut(SocketAddr) -> io::Result<UdpSocket>,
) -> io::Result<(TcpListener, UdpSocket)> {
    // A TCP-assigned port can be occupied or excluded for UDP, including on
    // Windows CI. Hold rejected TCP reservations until this search ends so
    // the OS cannot select the same candidate again. Never skip the test.
    let mut rejected = Vec::new();
    for attempt in 1..=MAX_BIND_ATTEMPTS {
        let tcp = TcpListener::bind("127.0.0.1:0")?;
        let address = tcp.local_addr()?;
        match bind_udp(address) {
            Ok(udp) => return Ok((tcp, udp)),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                ) =>
            {
                if attempt == MAX_BIND_ATTEMPTS {
                    return Err(io::Error::new(
                        error.kind(),
                        format!(
                            "could not reserve a TCP/UDP loopback pair after {attempt} attempts; \
                             last UDP bind at {address}: {error}"
                        ),
                    ));
                }
                rejected.push(tcp);
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("the final bind attempt always returns")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denied_and_occupied_udp_ports_select_fresh_candidates() {
        let mut candidates = Vec::new();
        let (tcp, udp) = bind_with_udp(|address| {
            assert!(!candidates.contains(&address));
            candidates.push(address);
            match candidates.len() {
                1 => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "excluded UDP port",
                )),
                2 => Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "occupied UDP port",
                )),
                _ => UdpSocket::bind(address),
            }
        })
        .unwrap();
        assert!(candidates.len() >= 3);
        assert_eq!(tcp.local_addr().unwrap(), udp.local_addr().unwrap());
    }

    #[test]
    fn persistent_denial_is_bounded_and_still_fails() {
        let mut attempts = 0;
        let error = bind_with_udp(|_| {
            attempts += 1;
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
        })
        .unwrap_err();
        assert_eq!(attempts, MAX_BIND_ATTEMPTS);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("after 32 attempts"));
    }

    #[test]
    fn unexpected_bind_errors_are_not_retried() {
        let mut attempts = 0;
        let error = bind_with_udp(|_| {
            attempts += 1;
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid socket",
            ))
        })
        .unwrap_err();
        assert_eq!(attempts, 1);
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
