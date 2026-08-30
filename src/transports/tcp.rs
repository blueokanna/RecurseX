//! DNS over TCP (RFC 7766): 2-byte length-prefixed messages.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::transport::{DnsTransport, MAX_TCP_MESSAGE};
use crate::upstream::{Endpoint, Proto};

/// The TCP transport.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpTransport {
    /// Maximum accepted message size (2-byte length prefix caps at 65535).
    pub max_message: usize,
    /// Whether to keep per-query connection setup minimal (we always open
    /// a fresh connection per exchange; pooling is the caller's concern).
    pub connect_timeout_ms: u64,
}

impl TcpTransport {
    /// Read a length-prefixed DNS message from `r`.
    fn read_message(r: &mut impl Read, max: usize) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 2];
        r.read_exact(&mut len_buf)
            .map_err(|e| Error::io(format!("tcp read length: {e}")))?;
        let len = u16::from_be_bytes(len_buf) as usize;
        if len > max {
            return Err(Error::transport(format!(
                "tcp message too large ({len} > {max})"
            )));
        }
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf)
            .map_err(|e| Error::io(format!("tcp read body: {e}")))?;
        Ok(buf)
    }
}

impl DnsTransport for TcpTransport {
    fn proto(&self) -> Proto {
        Proto::Tcp
    }

    fn exchange(&self, query: &[u8], endpoint: &Endpoint, timeout_ms: u64) -> Result<Vec<u8>> {
        if query.len() > MAX_TCP_MESSAGE {
            return Err(Error::transport("query too large for DNS-over-TCP"));
        }
        let addr = SocketAddr::new(endpoint.ip, endpoint.port);
        let timeout = Duration::from_millis(timeout_ms);
        let mut stream = std::net::TcpStream::connect_timeout(&addr, timeout)
            .map_err(|e| Error::io(format!("tcp connect {}: {e}", endpoint.addr_str())))?;
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|_| stream.set_write_timeout(Some(timeout)))
            .map_err(|e| Error::io(format!("tcp timeout setup: {e}")))?;

        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(query);
        stream
            .write_all(&framed)
            .map_err(|e| Error::io(format!("tcp write: {e}")))?;

        let resp = Self::read_message(&mut stream, self.max_message.max(MAX_TCP_MESSAGE))?;
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn read_message_roundtrip() {
        let payload = vec![1u8, 2, 3, 4];
        let mut framed = Vec::new();
        framed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        framed.extend_from_slice(&payload);
        let mut cur = std::io::Cursor::new(framed);
        let got = TcpTransport::read_message(&mut cur, 65535).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn read_message_rejects_oversize() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&0xffffu16.to_be_bytes());
        let mut cur = std::io::Cursor::new(framed);
        let r = TcpTransport::read_message(&mut cur, 100);
        assert!(r.is_err());
    }

    #[test]
    fn exchange_over_loopback() {
        // A minimal DNS response served over TCP.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = TcpTransport::read_message(&mut stream, 65535);
            let resp = vec![0xaa; 16];
            let mut framed = Vec::new();
            framed.extend_from_slice(&(resp.len() as u16).to_be_bytes());
            framed.extend_from_slice(&resp);
            let _ = stream.write_all(&framed);
        });
        let t = TcpTransport::default();
        let ep = Endpoint::new(addr.ip(), addr.port(), Proto::Tcp);
        let got = t.exchange(&[1, 2, 3], &ep, 2000).unwrap();
        assert_eq!(got, vec![0xaa; 16]);
        server.join().unwrap();
    }
}
