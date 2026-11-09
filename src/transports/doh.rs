//! DNS over HTTPS (RFC 8484) via courierust's HTTP/1.1 + HTTP/2 client.

use alloc::string::String;
use alloc::vec::Vec;

use courierust::courierust_tls::RootStore;

use crate::error::Result;
use crate::transport::DnsTransport;
use crate::upstream::{Endpoint, Proto};

/// DNS over HTTPS to a pinned IP. The current dependency requires the TLS
/// identity to be that IP literal; a separate hostname is rejected.
pub struct DohTransport {
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
    /// Lazily created, pooled courierust client (HTTP/1.1 + HTTP/2).
    client: super::http_dns::HttpDnsClient,
}

/// Identity and trust settings; the pooled client is deliberately not
/// touched, because `Debug` is called from log lines and panic messages and
/// must never block on a lock.
impl core::fmt::Debug for DohTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "DohTransport(hostname={:?}, path={:?}, verify={}, roots={})",
            self.hostname,
            self.path,
            self.verify,
            self.roots.len()
        )
    }
}

impl Default for DohTransport {
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

impl DohTransport {
    /// A DoH transport for `hostname` with the given roots.
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

impl DnsTransport for DohTransport {
    fn proto(&self) -> Proto {
        Proto::DoH
    }

    fn exchange(&self, query: &[u8], endpoint: &Endpoint, timeout_ms: u64) -> Result<Vec<u8>> {
        self.client.exchange(
            super::http_dns::Settings {
                host: &self.hostname,
                path: &self.path,
                roots: &self.roots,
                verify: self.verify,
                now: self.now,
                http3: false,
            },
            query,
            endpoint,
            timeout_ms,
        )
    }
}
