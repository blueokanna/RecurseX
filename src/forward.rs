//! Forwarding mode: resolve through configured upstreams (UDP/TCP/DoT/
//! DoH/DoH3/DoQ) with RD=1, instead of iterating from the root.
//!
//! This is the "upstream transport" layer of the architecture: the same
//! `ForwarderSet` serves forwarding deployments and can be extended to
//! query authoritative servers over encrypted transports.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use std::sync::Mutex;

use crate::error::{Error, ErrorKind, Result};
use crate::message::Message;
use crate::prng::SplitMix64;
use crate::query::response_matches_query;
use crate::transport::{DnsTransport, Transports};
use crate::upstream::{Endpoint, Proto};

/// A forwarding upstream.
#[derive(Clone, Debug)]
pub struct Forwarder {
    /// The upstream endpoint.
    pub endpoint: Endpoint,
    /// TLS server name for DoT / DoH / DoH3 / DoQ (SNI + verification).
    pub host: Option<String>,
}

impl Forwarder {
    /// A plain UDP/TCP forwarder.
    pub fn plain(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            host: None,
        }
    }

    /// An encrypted forwarder with its TLS identity.
    pub fn encrypted(endpoint: Endpoint, host: impl Into<String>) -> Self {
        Self {
            endpoint,
            host: Some(host.into()),
        }
    }
}

/// The set of forwarding upstreams with cached per-endpoint transports.
pub struct ForwarderSet {
    forwarders: Vec<Forwarder>,
    #[cfg(feature = "dot")]
    dot: Mutex<BTreeMap<Endpoint, crate::transports::dot::DotTransport>>,
    #[cfg(feature = "doh")]
    doh: Mutex<BTreeMap<Endpoint, crate::transports::doh::DohTransport>>,
    #[cfg(feature = "doh3")]
    doh3: Mutex<BTreeMap<Endpoint, crate::transports::doh3::Doh3Transport>>,
    #[cfg(feature = "doq")]
    doq: Mutex<BTreeMap<Endpoint, crate::transports::doq::DoqTransport>>,
    plain: Transports,
    roots: courierust::courierust_tls::RootStore,
    verify: bool,
    now: i64,
}

impl ForwarderSet {
    /// An empty set.
    pub fn new(roots: courierust::courierust_tls::RootStore, verify: bool, now: i64) -> Self {
        Self {
            forwarders: Vec::new(),
            #[cfg(feature = "dot")]
            dot: Mutex::new(BTreeMap::new()),
            #[cfg(feature = "doh")]
            doh: Mutex::new(BTreeMap::new()),
            #[cfg(feature = "doh3")]
            doh3: Mutex::new(BTreeMap::new()),
            #[cfg(feature = "doq")]
            doq: Mutex::new(BTreeMap::new()),
            plain: Transports::new(),
            roots,
            verify,
            now,
        }
    }

    /// The configured forwarders.
    pub fn forwarders(&self) -> &[Forwarder] {
        &self.forwarders
    }

    /// Add a forwarder.
    pub fn add(&mut self, f: Forwarder) {
        self.forwarders.push(f);
    }

    /// Whether any forwarders are configured.
    pub fn is_enabled(&self) -> bool {
        !self.forwarders.is_empty()
    }

    /// Send a query to the forwarders until one answers, validating the
    /// response against the query (ID + question echo).
    pub fn exchange(
        &self,
        query: &Message,
        query_bytes: &[u8],
        timeout_ms: u64,
    ) -> Result<Message> {
        let mut last_err: Option<Error> = None;
        for f in &self.forwarders {
            let resp_bytes = match self.exchange_one(f, query_bytes, timeout_ms) {
                Ok(b) => b,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            let resp = match Message::parse(&resp_bytes) {
                Ok(m) => m,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            if response_matches_query(query, &resp) {
                return Ok(resp);
            }
            last_err = Some(Error::transport("forwarder response did not match query"));
        }
        Err(last_err.unwrap_or_else(|| Error::new(ErrorKind::NoUpstream, "no forwarder answered")))
    }

    fn exchange_one(&self, f: &Forwarder, query: &[u8], timeout_ms: u64) -> Result<Vec<u8>> {
        match f.endpoint.proto {
            Proto::Udp | Proto::Tcp => self.plain.exchange(&f.endpoint, query, timeout_ms),
            #[cfg(feature = "dot")]
            Proto::Tls => {
                let mut cache = self.dot.lock().unwrap();
                let t = cache.entry(f.endpoint).or_insert_with(|| {
                    let host = f.host.clone().unwrap_or_else(|| f.endpoint.ip.to_string());
                    crate::transports::dot::DotTransport::for_host(
                        host,
                        self.roots.clone(),
                        self.verify,
                        self.now,
                    )
                });
                t.exchange(query, &f.endpoint, timeout_ms)
            }
            #[cfg(feature = "doh")]
            Proto::DoH => {
                let mut cache = self.doh.lock().unwrap();
                let t = cache.entry(f.endpoint).or_insert_with(|| {
                    let host = f.host.clone().unwrap_or_else(|| f.endpoint.ip.to_string());
                    crate::transports::doh::DohTransport::for_host(
                        host,
                        self.roots.clone(),
                        self.verify,
                        self.now,
                    )
                });
                t.exchange(query, &f.endpoint, timeout_ms)
            }
            #[cfg(feature = "doh3")]
            Proto::DoH3 => {
                let mut cache = self.doh3.lock().unwrap();
                let t = cache.entry(f.endpoint).or_insert_with(|| {
                    let host = f.host.clone().unwrap_or_else(|| f.endpoint.ip.to_string());
                    crate::transports::doh3::Doh3Transport::for_host(
                        host,
                        self.roots.clone(),
                        self.verify,
                        self.now,
                    )
                });
                t.exchange(query, &f.endpoint, timeout_ms)
            }
            #[cfg(feature = "doq")]
            Proto::DoQ => {
                let mut cache = self.doq.lock().unwrap();
                let t = cache.entry(f.endpoint).or_insert_with(|| {
                    let host = f.host.clone().unwrap_or_else(|| f.endpoint.ip.to_string());
                    crate::transports::doq::DoqTransport::for_host(
                        host,
                        self.roots.clone(),
                        self.verify,
                        self.now,
                    )
                });
                t.exchange(query, &f.endpoint, timeout_ms)
            }
            #[cfg(not(feature = "dot"))]
            Proto::Tls => Err(Error::new(
                ErrorKind::Unsupported,
                "DoT forwarder not compiled in (enable `dot`)",
            )),
            #[cfg(not(feature = "doh"))]
            Proto::DoH => Err(Error::new(
                ErrorKind::Unsupported,
                "DoH forwarder not compiled in (enable `doh`)",
            )),
            #[cfg(not(feature = "doh3"))]
            Proto::DoH3 => Err(Error::new(
                ErrorKind::Unsupported,
                "DoH3 forwarder not compiled in (enable `doh3`)",
            )),
            #[cfg(not(feature = "doq"))]
            Proto::DoQ => Err(Error::new(
                ErrorKind::Unsupported,
                "DoQ forwarder not compiled in (enable `doq`)",
            )),
        }
    }
}

/// Build a query message for a forwarder (RD=1, EDNS as requested).
pub fn build_forward_query(
    key: &crate::query::QueryKey,
    edns_udp_size: u16,
    dnssec: bool,
    rng: &mut SplitMix64,
) -> Message {
    let q = crate::engine::build_query(
        (rng.next_u32() & 0xffff) as u16,
        &key.name,
        key.rr_type,
        true,
        Some(&crate::engine::EdnsSpec {
            udp_size: edns_udp_size,
            dnssec_ok: dnssec || key.want_dnssec,
            ecs: crate::query::ecs_option(key),
            client_cookie: None,
        }),
        false,
        rng,
    );
    Message::parse(&q.bytes).unwrap_or_default()
}

/// Convert a forwarder response into a [`crate::resolver::Resolution`].
pub fn response_to_resolution(
    key: &crate::query::QueryKey,
    resp: &Message,
) -> crate::resolver::Resolution {
    let mut ttl = u32::MAX;
    let mut answers = Vec::new();
    let mut rrsigs = Vec::new();
    for r in &resp.answers {
        ttl = ttl.min(r.ttl);
        if r.rr_type == crate::qtype::RrType::RRSIG {
            rrsigs.push(r.clone());
        } else {
            answers.push(r.clone());
        }
    }
    if ttl == u32::MAX {
        ttl = 0;
    }
    crate::resolver::Resolution {
        name: key.name.clone(),
        rr_type: key.rr_type,
        class: key.class,
        rcode: crate::qtype::Rcode(resp.rcode() as u8),
        answers,
        authorities: resp.authorities.clone(),
        rrsigs,
        validated: false,
        ttl,
        from_cache: false,
        stale: false,
        served_at: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarder_defaults() {
        let set = ForwarderSet::new(courierust::courierust_tls::RootStore::new(), false, 0);
        assert!(!set.is_enabled());
        let mut set = set;
        set.add(Forwarder::plain(Endpoint::udp("1.1.1.1".parse().unwrap())));
        assert!(set.is_enabled());
        assert_eq!(set.forwarders().len(), 1);
    }
}
