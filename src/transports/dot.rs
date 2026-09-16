//! DNS over TLS (RFC 7858) via courierust's TLS 1.2/1.3 stack.

use alloc::string::String;
use alloc::vec::Vec;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use courierust::courierust_tls::{ClientConfig as TlsClientConfig, RootStore, TlsConnector};

use crate::error::{Error, Result};
use crate::transport::{DnsTransport, MAX_TCP_MESSAGE};
use crate::upstream::{Endpoint, Proto};

/// DNS over TLS transport. One instance carries one SNI/verification
/// hostname (the identity of the forwarder it talks to).
pub struct DotTransport {
    /// SNI + certificate verification name.
    pub hostname: String,
    /// Trust roots. Empty = no verification.
    pub roots: RootStore,
    /// Whether to verify the server certificate.
    pub verify: bool,
    /// Current unix time (seconds) for certificate validity.
    pub now: i64,
    /// Connect timeout in ms.
    pub connect_timeout_ms: u64,
}

impl core::fmt::Debug for DotTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "DotTransport(hostname={:?}, verify={}, roots={})",
            self.hostname,
            self.verify,
            self.roots.len()
        )
    }
}

impl Default for DotTransport {
    fn default() -> Self {
        Self {
            hostname: "localhost".into(),
            roots: RootStore::new(),
            verify: false,
            now: 0,
            connect_timeout_ms: 5000,
        }
    }
}

impl DotTransport {
    /// A transport for `hostname` (used for SNI and verification).
    pub fn for_host(hostname: impl Into<String>, roots: RootStore, verify: bool, now: i64) -> Self {
        Self {
            hostname: hostname.into(),
            roots,
            verify,
            now,
            connect_timeout_ms: 5000,
        }
    }

    fn connector(&self) -> TlsConnector {
        TlsConnector::new(TlsClientConfig {
            roots: self.roots.clone(),
            verify: self.verify,
            alpn: vec![b"dot".to_vec()],
            now: self.now,
            ..Default::default()
        })
    }
}

impl DnsTransport for DotTransport {
    fn proto(&self) -> Proto {
        Proto::Tls
    }

    fn exchange(&self, query: &[u8], endpoint: &Endpoint, timeout_ms: u64) -> Result<Vec<u8>> {
        if query.len() > MAX_TCP_MESSAGE {
            return Err(Error::transport("query too large for DoT"));
        }
        let timeout = Duration::from_millis(timeout_ms.max(self.connect_timeout_ms));
        let addr = SocketAddr::new(endpoint.ip, endpoint.port);
        let stream = TcpStream::connect_timeout(&addr, timeout)
            .map_err(|e| Error::io(format!("dot connect {}: {e}", endpoint.addr_str())))?;
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|_| stream.set_write_timeout(Some(timeout)))
            .map_err(|e| Error::io(format!("dot timeout setup: {e}")))?;

        let mut tls = self
            .connector()
            .connect(&self.hostname, &stream, &stream)
            .map_err(|e| Error::transport(format!("dot handshake: {e}")))?;

        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(query);
        tls.write_all(&framed)
            .map_err(|e| Error::io(format!("dot write: {e}")))?;

        // RFC 7858: responses are length-prefixed DNS messages.
        let mut len_buf = [0u8; 2];
        read_exact(&mut tls, &mut len_buf)?;
        let len = u16::from_be_bytes(len_buf) as usize;
        if len > MAX_TCP_MESSAGE {
            return Err(Error::transport(format!("dot message too large ({len})")));
        }
        let mut body = vec![0u8; len];
        read_exact(&mut tls, &mut body)?;
        Ok(body)
    }
}

/// Read exactly `buf.len()` bytes (the courierust io trait exposes `read`,
/// not `read_exact`).
fn read_exact(r: &mut impl courierust::courierust_io::Read, mut buf: &mut [u8]) -> Result<()> {
    while !buf.is_empty() {
        let n = r
            .read(buf)
            .map_err(|e| Error::io(format!("dot read: {e}")))?;
        if n == 0 {
            return Err(Error::transport("dot connection closed early"));
        }
        buf = &mut buf[n..];
    }
    Ok(())
}
