//! DNS over HTTP/3 (QUIC) via courierust's HTTP/3 client (ALPN `h3`).

use alloc::string::String;
use alloc::vec::Vec;

use courierust::courierust_tls::RootStore;

use crate::error::Result;
use crate::transport::DnsTransport;
use crate::upstream::{Endpoint, Proto};

/// DNS over HTTP/3 transport (the QUIC-based variant of DoH).
pub struct Doh3Transport {
    /// The literal IP identity authenticated by the certificate.
    pub hostname: String,
    /// The DoH URI path (default `/dns-query`).
    pub path: String,
    /// Trust roots.
    pub roots: RootStore,
    /// Whether to verify the server certificate.
    pub verify: bool,
    /// Fixed Unix seconds for replay; zero uses the live system clock.
    pub now: i64,
    /// Lazily created courierust HTTP/3 client (pooled QUIC connection).
    client: super::http_dns::HttpDnsClient,
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
            hostname: "8.8.8.8".into(),
            path: "/dns-query".into(),
            roots: RootStore::new(),
            verify: true,
            now: 0,
            client: super::http_dns::HttpDnsClient::default(),
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
            client: super::http_dns::HttpDnsClient::default(),
        }
    }
}

impl DnsTransport for Doh3Transport {
    fn proto(&self) -> Proto {
        Proto::DoH3
    }

    fn exchange(&self, query: &[u8], endpoint: &Endpoint, timeout_ms: u64) -> Result<Vec<u8>> {
        self.client.exchange(
            super::http_dns::Settings {
                host: &self.hostname,
                path: &self.path,
                roots: &self.roots,
                verify: self.verify,
                now: self.now,
                http3: true,
            },
            query,
            endpoint,
            timeout_ms,
        )
    }
}
