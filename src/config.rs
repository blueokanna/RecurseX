//! JSON configuration (nextjson).
//!
//! The whole resolver can be configured from one JSON document. `Config`
//! carries defaults for everything, so a minimal document like
//! `{"listen":[{"addr":"0.0.0.0:53","proto":"udp"}]}` is valid.

use alloc::string::String;
use alloc::vec::Vec;

use nextjson::{NsonDeserialize, NsonSerialize};

use crate::cache::CacheConfig;
use crate::error::{Error, Result};
use crate::planner::PlannerConfig;
use crate::policy::{BlockRule, PolicyConfig};
use crate::qtype::RrType;
use crate::resolver::{EngineConfig, RateLimitConfig, ResolverConfig};
use crate::upstream::{Endpoint, Proto};

/// Where the client-facing server listens.
#[derive(Debug, Clone, PartialEq, NsonSerialize, NsonDeserialize)]
#[njson(rename_all = "camelCase")]
pub struct ListenConfig {
    /// Socket address, e.g. `0.0.0.0:53` or `[::]:53`.
    pub addr: String,
    /// Transport: `udp`, `tcp`, `dot`, `doh`, `doh3`, `doq`.
    #[njson(default)]
    pub proto: String,
    /// TLS identity path prefix (for DoT; `.crt` + `.key` DER files).
    #[njson(default)]
    pub cert: Option<String>,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            addr: "0.0.0.0:53".into(),
            proto: "udp".into(),
            cert: None,
        }
    }
}

/// Cache tuning (JSON). All fields are optional; absent values fall back to
/// [`CacheConfig::default`], so a minimal document does not accidentally
/// disable the cache or zero a capacity.
#[derive(Debug, Clone, PartialEq, Default, NsonSerialize, NsonDeserialize)]
#[njson(rename_all = "camelCase")]
pub struct CacheJson {
    /// Hot tier capacity (entries); absent = default.
    #[njson(default)]
    pub hot_capacity: Option<usize>,
    /// Warm tier capacity (entries); absent = default.
    #[njson(default)]
    pub warm_capacity: Option<usize>,
    /// Cold tier capacity (entries); absent = default.
    #[njson(default)]
    pub cold_capacity: Option<usize>,
    /// NXDOMAIN store capacity (names); absent = default.
    #[njson(default)]
    pub nx_capacity: Option<usize>,
    /// Serve-stale window in seconds; absent = default.
    #[njson(default)]
    pub stale_window_secs: Option<u32>,
    /// Cap on negative TTLs; absent = default.
    #[njson(default)]
    pub negative_ttl_cap: Option<u32>,
    /// Absolute cap on positive TTLs; absent = default.
    #[njson(default)]
    pub max_ttl_cap: Option<u32>,
    /// Prefetch refresh threshold (remaining TTL); absent = default.
    #[njson(default)]
    pub prefetch_threshold_ttl: Option<u32>,
    /// Prefetch probability threshold; absent = default.
    #[njson(default)]
    pub prefetch_probability: Option<f64>,
}

impl CacheJson {
    /// Build a [`CacheConfig`], applying defaults for absent fields.
    pub fn into_cache(&self) -> CacheConfig {
        let d = CacheConfig::default();
        CacheConfig {
            hot_capacity: self.hot_capacity.unwrap_or(d.hot_capacity),
            warm_capacity: self.warm_capacity.unwrap_or(d.warm_capacity),
            cold_capacity: self.cold_capacity.unwrap_or(d.cold_capacity),
            nx_capacity: self.nx_capacity.unwrap_or(d.nx_capacity),
            stale_window_secs: self.stale_window_secs.unwrap_or(d.stale_window_secs),
            negative_ttl_cap: self.negative_ttl_cap.unwrap_or(d.negative_ttl_cap),
            max_ttl_cap: self.max_ttl_cap.unwrap_or(d.max_ttl_cap),
            prefetch_threshold_ttl: self
                .prefetch_threshold_ttl
                .unwrap_or(d.prefetch_threshold_ttl),
            prefetch_probability: self.prefetch_probability.unwrap_or(d.prefetch_probability),
            ..d
        }
    }
}

/// Engine tuning (JSON). All fields are optional; absent values fall back
/// to [`EngineConfig::default`].
#[derive(Debug, Clone, PartialEq, Default, NsonSerialize, NsonDeserialize)]
#[njson(rename_all = "camelCase")]
pub struct EngineJson {
    /// Root server addresses; empty = built-in default set.
    #[njson(default)]
    pub root_servers: Vec<String>,
    /// Query timeout in ms; absent = default.
    #[njson(default)]
    pub timeout_ms: Option<u64>,
    /// Enable QNAME minimization; absent = default.
    #[njson(default)]
    pub qname_minimization: Option<bool>,
    /// Enable 0x20 anti-spoofing; absent = default.
    #[njson(default)]
    pub use_0x20: Option<bool>,
    /// Maximum CNAME chain depth; absent = default.
    #[njson(default)]
    pub max_cname_depth: Option<usize>,
    /// Enable DNSSEC validation; absent = default.
    #[njson(default)]
    pub dnssec: Option<bool>,
    /// Fall back to TCP on truncation; absent = default.
    #[njson(default)]
    pub tcp_fallback: Option<bool>,
    /// Forwarding upstreams (optional): `{"proto":"dot","ip":"1.1.1.1","port":853,"host":"cloudflare-dns.com"}`.
    ///
    /// Configuring any forwarder switches the resolver to forwarding mode
    /// (RD=1 to the listed upstreams); `host` is required for the encrypted
    /// transports, because certificate verification uses it as the identity.
    #[njson(default)]
    pub forwarders: Vec<ForwarderJson>,
}

/// A forwarding upstream.
#[derive(Debug, Clone, PartialEq, NsonSerialize, NsonDeserialize)]
#[njson(rename_all = "camelCase")]
pub struct ForwarderJson {
    /// The upstream IP address.
    pub ip: String,
    /// The upstream port (0 = protocol default).
    #[njson(default)]
    pub port: u16,
    /// The transport: `udp` | `tcp` | `dot` | `doh` | `doh3` | `doq`.
    #[njson(default)]
    pub proto: String,
    /// TLS server name for DoT / DoH / DoH3 / DoQ.
    #[njson(default)]
    pub host: Option<String>,
}

impl ForwarderJson {
    /// Convert to an [`Endpoint`].
    pub fn endpoint(&self) -> Result<Endpoint> {
        let ip = self
            .ip
            .parse()
            .map_err(|_| Error::config(format!("bad upstream ip {}", self.ip)))?;
        let proto = match self.proto.as_str() {
            "udp" => Proto::Udp,
            "tcp" => Proto::Tcp,
            "dot" => Proto::Tls,
            "doh" => Proto::DoH,
            "doh3" => Proto::DoH3,
            "doq" => Proto::DoQ,
            other => {
                return Err(Error::config(format!("unknown upstream proto {other}")));
            }
        };
        let port = if self.port == 0 {
            match proto {
                Proto::Tls | Proto::DoQ | Proto::DoH3 => 853,
                Proto::DoH => 443,
                _ => 53,
            }
        } else {
            self.port
        };
        Ok(Endpoint::new(ip, port, proto))
    }

    /// Convert to a [`Forwarder`](crate::forward::Forwarder).
    ///
    /// An encrypted transport without a `host` is rejected: the SNI would
    /// fall back to the IP literal, and verification against an IP is not an
    /// identity check. Failing here is better than a resolver that cannot
    /// validate and degrades to full recursion.
    #[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
    pub fn forwarder(&self) -> Result<crate::forward::Forwarder> {
        let endpoint = self.endpoint()?;
        match endpoint.proto {
            Proto::Udp | Proto::Tcp => Ok(crate::forward::Forwarder::plain(endpoint)),
            Proto::Tls | Proto::DoH | Proto::DoH3 | Proto::DoQ => {
                let host = self.host.clone().ok_or_else(|| {
                    Error::config(format!(
                        "forwarder {}:{} ({}) requires \"host\" for TLS verification",
                        self.ip, self.port, self.proto
                    ))
                })?;
                Ok(crate::forward::Forwarder::encrypted(endpoint, host))
            }
        }
    }
}

/// Policy tuning (JSON).
#[derive(Debug, Clone, PartialEq, Default, NsonSerialize, NsonDeserialize)]
#[njson(rename_all = "camelCase")]
pub struct PolicyJson {
    /// Blocklist entries: `*.example.com` or exact names.
    #[njson(default)]
    pub block: Vec<String>,
}

impl PolicyJson {
    /// Build a [`PolicyConfig`], applying defaults for absent fields.
    pub fn into_policy(&self) -> PolicyConfig {
        let d = PolicyConfig::default();
        PolicyConfig {
            block: self
                .block
                .iter()
                .filter_map(|s| crate::name::Name::from_ascii(s).ok())
                .map(BlockRule::subtree)
                .collect(),
            ..d
        }
    }
}

/// L3 persistent cache tuning (JSON; persist feature).
#[cfg(feature = "persist")]
#[derive(Debug, Clone, PartialEq, NsonSerialize, NsonDeserialize)]
#[njson(rename_all = "camelCase")]
pub struct PersistJson {
    /// Snapshot path; `null` disables the persistent tier.
    pub path: Option<String>,
    /// Periodic save interval in ms (0 = only explicit saves).
    #[njson(default)]
    pub save_interval_ms: u64,
    /// Maximum accepted frame size in bytes on load.
    #[njson(default)]
    pub frame_limit: u64,
}

#[cfg(feature = "persist")]
impl Default for PersistJson {
    fn default() -> Self {
        Self {
            path: None,
            save_interval_ms: 60_000,
            frame_limit: 32 * 1024 * 1024,
        }
    }
}

#[cfg(feature = "persist")]
impl PersistJson {
    /// Build a [`crate::cache::persist::PersistConfig`]; `None` when no path
    /// is configured.
    pub fn into_persist(&self) -> Option<crate::cache::persist::PersistConfig> {
        let path = self.path.as_ref()?;
        let mut c = crate::cache::persist::PersistConfig::new(
            std::path::PathBuf::from(path),
            self.save_interval_ms,
        );
        c.frame_limit = self.frame_limit.max(1024);
        Some(c)
    }
}

/// The full resolver configuration document.
#[derive(Debug, Clone, PartialEq, NsonSerialize, NsonDeserialize)]
#[njson(rename_all = "camelCase")]
pub struct Config {
    /// Listen addresses for the server mode.
    #[njson(default)]
    pub listen: Vec<ListenConfig>,
    /// Cache tuning.
    #[njson(default)]
    pub cache: CacheJson,
    /// Engine tuning.
    #[njson(default)]
    pub engine: EngineJson,
    /// Policy (blocklist) tuning.
    #[njson(default)]
    pub policy: PolicyJson,
    /// Client rate limit: queries per second per client (absent = default).
    #[njson(default)]
    pub client_qps: Option<f64>,
    /// Client rate limit burst (absent = default).
    #[njson(default)]
    pub client_burst: Option<f64>,
    /// Maintenance loop interval in ms (absent = default).
    #[njson(default)]
    pub maintenance_interval_ms: Option<u64>,
    /// L3 persistent cache (persist feature): `{"path":"cache.rxc","saveIntervalMs":60000}`.
    #[cfg(feature = "persist")]
    #[njson(default)]
    pub persist: Option<PersistJson>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: vec![ListenConfig::default()],
            cache: CacheJson::default(),
            engine: EngineJson::default(),
            policy: PolicyJson::default(),
            client_qps: None,
            client_burst: None,
            maintenance_interval_ms: None,
            #[cfg(feature = "persist")]
            persist: None,
        }
    }
}

impl Config {
    /// Parse a configuration document from JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Config> {
        nextjson::nextdecode(bytes).map_err(|e| Error::config(format!("bad config JSON: {e}")))
    }

    /// Parse from a JSON string.
    pub fn from_json_str(s: &str) -> Result<Config> {
        Self::from_json(s.as_bytes())
    }

    /// Serialize this configuration to compact JSON.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        nextjson::nextencode(self).map_err(|e| Error::config(format!("config encode: {e}")))
    }

    /// Build a [`ResolverConfig`] from this document.
    pub fn into_resolver_config(&self) -> Result<ResolverConfig> {
        let d = ResolverConfig::default();
        let engine = self.engine.clone();
        let root_servers = engine
            .root_servers
            .iter()
            .filter_map(|s| parse_root(s))
            .collect();
        let mut ec = EngineConfig {
            root_servers,
            timeout_ms: engine.timeout_ms.unwrap_or(d.engine.timeout_ms),
            qname_minimization: engine
                .qname_minimization
                .unwrap_or(d.engine.qname_minimization),
            use_0x20: engine.use_0x20.unwrap_or(d.engine.use_0x20),
            max_cname_depth: engine.max_cname_depth.unwrap_or(d.engine.max_cname_depth),
            tcp_fallback: engine.tcp_fallback.unwrap_or(d.engine.tcp_fallback),
            ..d.engine
        };
        #[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
        {
            ec.forwarders = engine
                .forwarders
                .iter()
                .map(ForwarderJson::forwarder)
                .collect::<Result<Vec<_>>>()?;
        }
        #[cfg(not(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq")))]
        if !engine.forwarders.is_empty() {
            return Err(Error::config(
                "forwarders require a build with the dot, doh, doh3 or doq feature",
            ));
        }
        ec.dnssec = engine.dnssec.unwrap_or(d.engine.dnssec) && cfg!(feature = "dnssec");
        let client_burst = self.client_burst.unwrap_or(d.rate_limit.client_capacity);
        let client_qps = self
            .client_qps
            .unwrap_or(d.rate_limit.client_refill_per_sec);
        Ok(ResolverConfig {
            cache: self.cache.into_cache(),
            planner: PlannerConfig::default(),
            policy: self.policy.into_policy(),
            engine: ec,
            rate_limit: RateLimitConfig {
                client_capacity: client_burst.max(1.0),
                client_refill_per_sec: client_qps.max(0.0),
                max_client_buckets: d.rate_limit.max_client_buckets,
            },
            maintenance_interval_ms: self
                .maintenance_interval_ms
                .unwrap_or(d.maintenance_interval_ms),
            #[cfg(feature = "persist")]
            persist: self.persist.as_ref().and_then(PersistJson::into_persist),
            ..d
        })
    }
}

/// Parse one `rootServers` entry: `"198.41.0.4"` (port 53) or
/// `"198.41.0.4:5353"`. Returns `None` for anything else, so a typo drops
/// that entry rather than silently querying an unintended address.
fn parse_root(s: &str) -> Option<std::net::SocketAddr> {
    if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
        return Some(sa);
    }
    s.parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| std::net::SocketAddr::new(ip, 53))
}

/// A helper: parse a record-type name like `A`, `AAAA`, `HTTPS`.
pub fn parse_rr_type(s: &str) -> Option<RrType> {
    let up = s.to_ascii_uppercase();
    match up.as_str() {
        "A" => Some(RrType::A),
        "AAAA" => Some(RrType::AAAA),
        "CNAME" => Some(RrType::CNAME),
        "MX" => Some(RrType::MX),
        "NS" => Some(RrType::NS),
        "TXT" => Some(RrType::TXT),
        "SOA" => Some(RrType::SOA),
        "PTR" => Some(RrType::PTR),
        "SRV" => Some(RrType::SRV),
        "CAA" => Some(RrType::CAA),
        "HTTPS" => Some(RrType::HTTPS),
        "SVCB" => Some(RrType::SVCB),
        "DS" => Some(RrType::DS),
        "DNSKEY" => Some(RrType::DNSKEY),
        "TLSA" => Some(RrType::TLSA),
        "ANY" => Some(RrType::ANY),
        _ => {
            if let Ok(n) = up.trim_start_matches("TYPE").parse::<u16>() {
                Some(RrType(n))
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip() {
        let c = Config::default();
        let bytes = c.to_json().unwrap();
        let back: Config = Config::from_json(&bytes).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn minimal_document_parses() {
        let c = Config::from_json_str(r#"{"listen":[{"addr":"127.0.0.1:5353","proto":"udp"}]}"#)
            .unwrap();
        assert_eq!(c.listen.len(), 1);
        assert_eq!(c.listen[0].addr, "127.0.0.1:5353");
        let rc = c.into_resolver_config().unwrap();
        assert!(rc.engine.timeout_ms > 0);
    }

    /// A minimal document must fall back to the resolver defaults for every
    /// absent tuning field — a regression guard for the Option-based JSON
    /// mapping (absent must never zero the timeout, disable 0x20/QNAME
    /// minimization, or zero the cache capacities).
    #[test]
    fn minimal_document_keeps_resolver_defaults() {
        let d = ResolverConfig::default();
        let rc = Config::from_json_str(r#"{"listen":[]}"#)
            .unwrap()
            .into_resolver_config()
            .unwrap();
        assert_eq!(rc.engine.timeout_ms, d.engine.timeout_ms);
        assert_eq!(rc.engine.qname_minimization, d.engine.qname_minimization);
        assert_eq!(rc.engine.use_0x20, d.engine.use_0x20);
        assert_eq!(rc.engine.tcp_fallback, d.engine.tcp_fallback);
        assert_eq!(rc.cache.hot_capacity, d.cache.hot_capacity);
        assert_eq!(rc.cache.warm_capacity, d.cache.warm_capacity);
        assert_eq!(
            rc.rate_limit.client_refill_per_sec,
            d.rate_limit.client_refill_per_sec
        );
        assert_eq!(rc.maintenance_interval_ms, d.maintenance_interval_ms);
        assert!(rc.cache.hot_capacity > 0 && rc.engine.timeout_ms > 0);
    }

    /// Explicit values override the defaults.
    #[test]
    fn explicit_values_override_defaults() {
        let rc = Config::from_json_str(
            r#"{
                "engine": { "timeoutMs": 700, "qnameMinimization": false, "use0x20": false },
                "clientQps": 5.0, "clientBurst": 10.0
            }"#,
        )
        .unwrap()
        .into_resolver_config()
        .unwrap();
        assert_eq!(rc.engine.timeout_ms, 700);
        assert!(!rc.engine.qname_minimization);
        assert!(!rc.engine.use_0x20);
        assert_eq!(rc.rate_limit.client_refill_per_sec, 5.0);
        assert_eq!(rc.rate_limit.client_capacity, 10.0);
    }

    #[test]
    fn forwarder_default_port() {
        let f = ForwarderJson {
            ip: "1.1.1.1".into(),
            port: 0,
            proto: "dot".into(),
            host: Some("cloudflare-dns.com".into()),
        };
        let ep = f.endpoint().unwrap();
        assert_eq!(ep.port, 853);
        assert_eq!(ep.proto, Proto::Tls);
    }

    #[test]
    fn rr_type_parsing() {
        assert_eq!(parse_rr_type("A"), Some(RrType::A));
        assert_eq!(parse_rr_type("https"), Some(RrType::HTTPS));
        assert_eq!(parse_rr_type("TYPE1234"), Some(RrType(1234)));
        assert_eq!(parse_rr_type("NOPE"), None);
    }
}
