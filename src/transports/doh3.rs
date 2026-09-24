//! DNS over HTTP/3 (QUIC) via courierust's HTTP/3 client (ALPN `h3`).

use crate::sync::Mutex;
use alloc::string::String;
use alloc::vec::Vec;

use courierust::courierust_client::{Client, ClientConfig, TlsSettings};
use courierust::courierust_tls::RootStore;

use crate::error::{Error, Result};
use crate::transport::{DnsTransport, MAX_TCP_MESSAGE};
use crate::upstream::{Endpoint, Proto};

/// DNS over HTTP/3 transport (the QUIC-based variant of DoH).
pub struct Doh3Transport {
    /// The HTTPS authority hostname.
    pub hostname: String,
    /// The DoH URI path (default `/dns-query`).
    pub path: String,
    /// Trust roots.
    pub roots: RootStore,
    /// Whether to verify the server certificate.
    pub verify: bool,
    /// Current unix time (seconds) for certificate validity.
    pub now: i64,
    /// Lazily created courierust HTTP/3 client (pooled QUIC connection).
    client: Mutex<Option<Client>>,
}

/// Identity and trust settings; the pooled client is deliberately not
/// touched (`Debug` must never block on a lock).
impl core::fmt::Debug for Doh3Transport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Doh3Transport(hostname={:?}, path={:?}, verify={}, roots={})",
            self.hostname,
            self.path,
            self.verify,
            self.roots.len()
        )
    }
}

impl Default for Doh3Transport {
    fn default() -> Self {
        Self {
            hostname: "dns.google".into(),
            path: "/dns-query".into(),
            roots: RootStore::new(),
            verify: false,
            now: 0,
            client: Mutex::new(None),
        }
    }
}

impl Doh3Transport {
    /// A DoH3 transport for `hostname`.
    pub fn for_host(hostname: impl Into<String>, roots: RootStore, verify: bool, now: i64) -> Self {
        Self {
            hostname: hostname.into(),
            path: "/dns-query".into(),
            roots,
            verify,
            now,
            client: Mutex::new(None),
        }
    }

    fn client(&self) -> Result<Client> {
        let mut guard = self.client.lock();
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let cfg = ClientConfig {
            http3: true,
            max_connections_per_host: 1,
            tls: Some(TlsSettings {
                roots: self.roots.clone(),
                verify: self.verify,
                alpn: vec![b"h3".to_vec()],
                now: self.now,
                ..Default::default()
            }),
            max_body: MAX_TCP_MESSAGE,
            ..Default::default()
        };
        let client = Client::with_config(cfg);
        *guard = Some(client.clone());
        Ok(client)
    }
}

impl DnsTransport for Doh3Transport {
    fn proto(&self) -> Proto {
        Proto::DoH3
    }

    fn exchange(&self, query: &[u8], endpoint: &Endpoint, timeout_ms: u64) -> Result<Vec<u8>> {
        let client = self.client()?;
        let url = format!("https://{}:{}{}", self.hostname, endpoint.port, self.path);
        let resp = client
            .post(&url, query.to_vec())
            .map_err(|e| Error::transport(format!("doh3 request: {e}")))?;
        if resp.status.as_u16() != 200 {
            return Err(Error::transport(format!(
                "doh3 status {} from {}",
                resp.status.as_u16(),
                self.hostname
            )));
        }
        let body = resp
            .body
            .collect()
            .map_err(|e| Error::transport(format!("doh3 body: {e}")))?;
        if body.len() > MAX_TCP_MESSAGE {
            return Err(Error::transport("doh3 response too large"));
        }
        let _ = timeout_ms;
        Ok(body.to_vec())
    }
}
