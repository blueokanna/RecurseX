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
///
/// `deny_unknown_fields`: a misspelled key is an error that names it. The
/// alternative is a setting that parses, is dropped, and leaves the operator
/// believing it took effect — the failure mode this whole section exists to
/// remove.
#[derive(Debug, Clone, PartialEq, NsonSerialize, NsonDeserialize)]
#[njson(rename_all = "camelCase", deny_unknown_fields)]
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
#[njson(rename_all = "camelCase", deny_unknown_fields)]
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
#[njson(rename_all = "camelCase", deny_unknown_fields)]
pub struct EngineJson {
    /// Root server addresses; empty = built-in default set.
    #[njson(default)]
    pub root_servers: Vec<String>,
    /// Query timeout in ms; absent = default.
    #[njson(default)]
    pub timeout_ms: Option<u64>,
    /// Wall-clock budget for one client query in ms, covering the whole
    /// delegated tree it spawns; absent = default (20 000).
    ///
    /// Accepted as `queryBudgetMs`, `query_budget_ms` or `query-budget-ms`:
    /// this struct denies unknown keys, so a wrong guess is a hard error rather
    /// than a silently ignored setting, and the three spellings cost nothing.
    #[njson(default, alias = "query_budget_ms", alias = "query-budget-ms")]
    pub query_budget_ms: Option<u64>,
    /// Port for authoritative servers discovered during a resolution; absent =
    /// 53. Exists so the iterative walk can be tested without a privileged
    /// port — see `EngineConfig::auth_port`.
    #[njson(default, alias = "auth_port", alias = "auth-port")]
    pub auth_port: Option<u16>,
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
#[njson(rename_all = "camelCase", deny_unknown_fields)]
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
#[njson(rename_all = "camelCase", deny_unknown_fields)]
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

/// One `hosts` value: a single address or a list of them.
///
/// Untagged so the Clash spelling works. In YAML, `hosts: {a.com: 1.2.3.4}`
/// and `hosts: {a.com: [1.2.3.4, ::1]}` are both natural, and a JSON port of
/// either should not have to be rewritten to be accepted.
#[derive(Debug, Clone, PartialEq, NsonSerialize, NsonDeserialize)]
#[njson(untagged)]
pub enum HostValue {
    /// A single address.
    One(String),
    /// Several addresses.
    Many(Vec<String>),
}

impl HostValue {
    /// The value as a slice, whichever shape it arrived in.
    pub fn as_slice(&self) -> &[String] {
        match self {
            HostValue::One(s) => std::slice::from_ref(s),
            HostValue::Many(v) => v.as_slice(),
        }
    }
}

/// Answer-quality gate (`fallback-filter`).
///
/// `geoip` and `geoipCode` are accepted so a ported Clash config parses, and
/// refused when actually set — see
/// [`FallbackFilter::new`](crate::routing::FallbackFilter::new) for why
/// silently accepting them would be the worst outcome.
#[derive(Debug, Clone, PartialEq, Default, NsonSerialize, NsonDeserialize)]
#[njson(rename_all = "camelCase", deny_unknown_fields)]
pub struct FallbackFilterJson {
    /// Geographic filtering; requires a country database this build does not
    /// embed.
    #[njson(default)]
    pub geoip: bool,
    /// The country codes `geoip` would have used.
    #[njson(default, alias = "geoip-code", alias = "geoip_code")]
    pub geoip_code: Vec<String>,
    /// Address blocks that mark an answer as poisoned. Absent = the built-in
    /// set; an explicit empty list means "flag nothing".
    #[njson(default)]
    pub ipcidr: Option<Vec<String>>,
    /// Names that always use the fallback servers.
    #[njson(default)]
    pub domain: Vec<String>,
}

/// The Clash-compatible DNS policy section.
///
/// Field names follow the crate's `camelCase` JSON convention, and every
/// field also accepts the Clash spelling. Three spellings work for each:
/// `nameserver-policy` (Clash), `nameserver_policy` (this crate's Rust name),
/// and `nameserverPolicy` (the primary JSON name). Accepting all three is
/// deliberate — those keys are what people copy out of an existing proxy
/// config, and the alternative is a key that parses but does nothing.
///
/// Every struct in this section declares `deny_unknown_fields`. An unknown
/// key is a configuration error naming the key, not a silently ignored
/// setting: a `nameserver-policy` that a client writes and this resolver
/// drops is indistinguishable from a policy that does not work.
#[derive(Debug, Clone, PartialEq, Default, NsonSerialize, NsonDeserialize)]
#[njson(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsJson {
    /// `enhanced-mode`: `normal` (the default) or `fake-ip`.
    #[njson(default, alias = "enhanced-mode", alias = "enhanced_mode")]
    pub enhanced_mode: Option<String>,
    /// The fake-IP address range.
    #[njson(default, alias = "fake-ip-range", alias = "fake_ip_range")]
    pub fake_ip_range: Option<String>,
    /// The IPv6 fake-IP range. **Its presence is what makes `AAAA`
    /// synthesized instead of answered NODATA** — synthesizing a v6 address
    /// is what lets a dual-stack client connect over IPv6, so it is opt-in.
    #[njson(default, alias = "fake-ip-range6", alias = "fake_ip_range6")]
    pub fake_ip_range6: Option<String>,
    /// Names excluded from fake-IP. **Absent** takes the built-in list
    /// (connectivity probes, NTP, STUN and local names, which break in
    /// visible ways when they are faked); an explicit empty list means "no
    /// exclusions", which is a different statement.
    #[njson(default, alias = "fake-ip-filter", alias = "fake_ip_filter")]
    pub fake_ip_filter: Option<Vec<String>>,
    /// How long a fake-IP *mapping* may live, in seconds.
    #[njson(default, alias = "fake-ip-ttl", alias = "fake_ip_ttl")]
    pub fake_ip_ttl: Option<u64>,
    /// The TTL carried by a synthesized fake-IP *answer*, in seconds.
    #[njson(default, alias = "fake-ip-answer-ttl", alias = "fake_ip_answer_ttl")]
    pub fake_ip_answer_ttl: Option<u32>,
    /// Cap on live fake-IP mappings.
    #[njson(default, alias = "fake-ip-max-entries", alias = "fake_ip_max_entries")]
    pub fake_ip_max_entries: Option<usize>,
    /// Static answers, by name.
    #[njson(default)]
    pub hosts: std::collections::BTreeMap<String, HostValue>,
    /// TTL for `hosts` answers.
    #[njson(default, alias = "hosts-ttl", alias = "hosts_ttl")]
    pub hosts_ttl: Option<u32>,
    /// Default upstreams. Mutually exclusive with `engine.forwarders`.
    #[njson(default)]
    pub nameservers: Vec<String>,
    /// Upstreams the fallback filter sends queries to.
    #[njson(default)]
    pub fallback: Vec<String>,
    /// Per-suffix upstreams (`nameserver-policy`).
    #[njson(default, alias = "nameserver-policy", alias = "nameserver_policy")]
    pub nameserver_policy: std::collections::BTreeMap<String, Vec<String>>,
    /// The answer-quality gate.
    #[njson(default, alias = "fallback-filter", alias = "fallback_filter")]
    pub fallback_filter: Option<FallbackFilterJson>,
}

/// Parse one upstream string into a forwarder.
///
/// Accepted forms — the address is always an IP literal:
///
/// | Spelling                              | Transport |
/// |---------------------------------------|-----------|
/// | `1.2.3.4`, `1.2.3.4:5353`, `1.2.3.4@5353` | UDP   |
/// | `udp://1.2.3.4`, `tcp://1.2.3.4:53`   | UDP / TCP |
/// | `tls://1.2.3.4#dns.example`           | DoT       |
/// | `https://1.2.3.4/dns-query#dns.example` | DoH     |
/// | `h3://1.2.3.4/dns-query#dns.example`  | DoH3      |
/// | `quic://1.2.3.4#dns.example`          | DoQ       |
/// | `[2001:db8::1]:853#dns.example`       | IPv6, in brackets |
///
/// The `#name` fragment is the TLS identity: the SNI sent and the name the
/// certificate must match. The encrypted transports require it, because
/// verifying a certificate against an IP literal is not an identity check.
///
/// The port may follow either `:` or `@`. Unbound writes it with `@`
/// (`forward-addr: 1.1.1.1@853#cloudflare-dns.com`), so a forwarder line can
/// be copied from an Unbound configuration and keep working.
///
/// # Why the address may not be a hostname
///
/// `tls://dns.google` would have to be resolved before the resolver exists.
/// Doing that with the system resolver would make the resolver silently
/// depend on whatever `/etc/resolv.conf` happens to say — the one dependency
/// a resolver must not have, because it is the thing that is supposed to be
/// broken when you install it. Unbound solves the same problem the same way
/// (an address plus an explicit TLS name), so the limitation is a convention
/// rather than a gap: the address and the identity are separate fields, and
/// the operator supplies both.
#[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
pub fn parse_upstream(s: &str) -> Result<crate::forward::Forwarder> {
    // The identity fragment first: it may contain a colon (a port-looking
    // suffix in a name is legal), so it has to come off before the authority
    // is split.
    let (rest, name) = match s.split_once('#') {
        Some((a, b)) => (a.trim(), Some(b.trim())),
        None => (s.trim(), None),
    };
    if rest.is_empty() {
        return Err(Error::config(format!("empty upstream string: {s:?}")));
    }
    if let Some(n) = name {
        if n.is_empty() {
            return Err(Error::config(format!(
                "upstream {s:?} has an empty \"#name\" fragment; remove the \"#\" or name the \
                 TLS identity"
            )));
        }
    }

    let (scheme, rest) = match rest.split_once("://") {
        Some((sch, r)) => (sch.to_ascii_lowercase(), r),
        None => ("udp".to_string(), rest),
    };
    if rest.is_empty() {
        return Err(Error::config(format!("upstream {s:?} has no address")));
    }

    let default_port = match scheme.as_str() {
        "udp" | "tcp" => 53,
        "tls" | "quic" => 853,
        "https" | "h3" => 443,
        other => {
            return Err(Error::config(format!(
                "upstream {s:?}: unknown scheme {other:?} (expected udp, tcp, tls, https, h3 \
                 or quic)"
            )));
        }
    };

    // DoH/DoH3 carry a URI path; the other schemes have none, so a `/` in
    // them is a typo worth reporting rather than a path to ignore.
    let want_path = matches!(scheme.as_str(), "https" | "h3");
    let (authority, path) = match rest.split_once('/') {
        Some((auth, p)) => {
            if !want_path {
                return Err(Error::config(format!(
                    "upstream {s:?}: {scheme}:// takes no path"
                )));
            }
            (auth, Some(p))
        }
        None => (rest, None),
    };

    let ip = parse_authority(authority).ok_or_else(|| {
        Error::config(format!(
            "upstream {s:?}: {authority:?} is not an IP literal (a hostname upstream is not \
             supported; write the address, e.g. tls://1.1.1.1#one.one.one.one)"
        ))
    })?;
    let (ip, port) = ip;
    let port = port.unwrap_or(default_port);
    if port == 0 {
        return Err(Error::config(format!(
            "upstream {s:?}: port 0 is not a port"
        )));
    }

    let proto = match scheme.as_str() {
        "udp" => Proto::Udp,
        "tcp" => Proto::Tcp,
        "tls" => Proto::Tls,
        "https" => Proto::DoH,
        "h3" => Proto::DoH3,
        _ => Proto::DoQ,
    };
    let endpoint = Endpoint::new(ip, port, proto);
    if matches!(proto, Proto::Udp | Proto::Tcp) {
        if name.is_some() {
            return Err(Error::config(format!(
                "upstream {s:?}: a plain {scheme}:// upstream carries no TLS identity"
            )));
        }
        return Ok(crate::forward::Forwarder::plain(endpoint));
    }
    let name = name.ok_or_else(|| {
        Error::config(format!(
            "upstream {s:?}: the encrypted transports need a TLS name to verify against; \
             append it, e.g. {scheme}://{ip}#dns.example"
        ))
    })?;
    let f = crate::forward::Forwarder::encrypted(endpoint, name);
    Ok(match path {
        // An absent path means the RFC 8484 default, which is what every
        // large public DoH service uses.
        None | Some("") => f,
        Some(p) => f.with_path(format!("/{p}")),
    })
}

/// Split `host[:port]` (or `host@port`) with an IPv6 literal in brackets.
/// Returns the address and any explicit port, or `None` when the host is not
/// an IP literal.
#[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
fn parse_authority(authority: &str) -> Option<(std::net::IpAddr, Option<u16>)> {
    let authority = authority.trim();
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literals must be bracketed, or `::1:853` is ambiguous.
        let (host, tail) = rest.split_once(']')?;
        let port = match tail {
            "" => None,
            t => Some(
                t.strip_prefix(':')
                    .or_else(|| t.strip_prefix('@'))?
                    .parse()
                    .ok()?,
            ),
        };
        return Some((host.parse().ok()?, port));
    }
    // Unbound's spelling. `@` can never occur inside an address, so unlike a
    // bare `:` it is unambiguous — and a line copied out of an Unbound
    // `forward-addr` keeps working here.
    if let Some((host, port)) = authority.rsplit_once('@') {
        return Some((host.parse().ok()?, Some(port.parse().ok()?)));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => match (host.parse(), port.parse::<u16>()) {
            (Ok(ip), Ok(p)) => Some((ip, Some(p))),
            // Not `host:port`. A bare IPv6 literal lands here, because its
            // last colon separates two hextets rather than a port.
            _ => authority.parse().ok().map(|ip| (ip, None)),
        },
        None => authority.parse().ok().map(|ip| (ip, None)),
    }
}

/// L3 persistent cache tuning (JSON; persist feature).
#[cfg(feature = "persist")]
#[derive(Debug, Clone, PartialEq, NsonSerialize, NsonDeserialize)]
#[njson(rename_all = "camelCase", deny_unknown_fields)]
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
#[njson(rename_all = "camelCase", deny_unknown_fields)]
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
    /// Clash-compatible DNS policy: `hosts`, `enhanced-mode`/fake-IP,
    /// `nameservers`, `fallback`, `nameserver-policy`, `fallback-filter`.
    #[njson(default)]
    pub dns: DnsJson,
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
            dns: DnsJson::default(),
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

    /// Build the Clash-compatible policy layer from the `dns` section.
    ///
    /// An empty `dns` section produces a default-valued policy, and a default
    /// policy is byte-for-byte the pre-existing behaviour: no pins, no
    /// synthesis, no routing, and the built-in bogus-range list as the only
    /// filter — which does nothing on its own, because the poison gate needs a
    /// `fallback` group to have somewhere to send the query.
    fn build_dns_policy(&self) -> Result<crate::resolver::DnsPolicy> {
        use crate::fakeip::{
            FakeIpSettings, DEFAULT_FAKE_IP_MAX_ENTRIES, DEFAULT_FAKE_IP_RANGE,
            DEFAULT_FAKE_IP_TTL_SECS,
        };

        let dns = &self.dns;

        // A configuration that names its upstreams twice is ambiguous, and
        // picking one silently is how the two lists drift apart.
        if !dns.nameservers.is_empty() && !self.engine.forwarders.is_empty() {
            return Err(Error::config(
                "set either `dns.nameservers` or `engine.forwarders`, not both: they are the \
                 same setting in two spellings, and one would be ignored",
            ));
        }

        // --- hosts -----------------------------------------------------
        let mut hosts =
            crate::hosts::HostsTable::new(dns.hosts_ttl.unwrap_or(crate::hosts::DEFAULT_HOSTS_TTL));
        for (name, value) in &dns.hosts {
            hosts.insert_from_config(name, value.as_slice())?;
        }

        // --- enhanced-mode / fake-IP -----------------------------------
        let mode = dns
            .enhanced_mode
            .as_deref()
            .unwrap_or("normal")
            .trim()
            .to_ascii_lowercase();
        let fake_ip = match mode.as_str() {
            // `redir-host` is Clash's other enhanced mode: it resolves
            // normally and lets the proxy use the real address, so there is
            // nothing to synthesize.
            "" | "normal" | "redir-host" => None,
            "fake-ip" | "fakeip" | "fake_ip" => {
                let mut s = FakeIpSettings::parse(
                    dns.fake_ip_range
                        .as_deref()
                        .unwrap_or(DEFAULT_FAKE_IP_RANGE),
                    dns.fake_ip_range6.as_deref(),
                    dns.fake_ip_filter.as_deref(),
                    dns.fake_ip_ttl.unwrap_or(DEFAULT_FAKE_IP_TTL_SECS),
                    dns.fake_ip_max_entries
                        .unwrap_or(DEFAULT_FAKE_IP_MAX_ENTRIES),
                )?;
                if let Some(t) = dns.fake_ip_answer_ttl {
                    s = s.with_answer_ttl(t);
                }
                Some(s)
            }
            other => {
                return Err(Error::config(format!(
                    "dns.enhanced-mode {other:?} is not a mode (expected \"normal\", \
                     \"redir-host\" or \"fake-ip\")"
                )));
            }
        };

        // --- fallback-filter ------------------------------------------
        let fallback = match &dns.fallback_filter {
            Some(f) => {
                // `geoipCode` is only ever read by `geoip`, which this build
                // refuses. Accepting the list quietly would look like
                // country filtering was configured.
                if !f.geoip_code.is_empty() {
                    return Err(Error::config(
                        "dns.fallback-filter.geoipCode has no effect: this build embeds no \
                         country database; use `ipcidr` to list the ranges that count as \
                         pollution",
                    ));
                }
                crate::routing::FallbackFilter::new(&f.domain, f.ipcidr.as_deref(), f.geoip)?
            }
            None => crate::routing::FallbackFilter::default(),
        };

        // --- upstreams and suffix policy -------------------------------
        #[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
        let (upstreams, policy) = {
            let default = if dns.nameservers.is_empty() {
                // The legacy spelling, already fully specified as endpoints.
                self.engine
                    .forwarders
                    .iter()
                    .map(ForwarderJson::forwarder)
                    .collect::<Result<Vec<_>>>()?
            } else {
                dns.nameservers
                    .iter()
                    .map(|s| parse_upstream(s))
                    .collect::<Result<Vec<_>>>()?
            };
            let fallback = dns
                .fallback
                .iter()
                .map(|s| parse_upstream(s))
                .collect::<Result<Vec<_>>>()?;

            // Policy groups. `nameserver_policy` is a BTreeMap, so ids are
            // assigned in a fixed order and a group id means the same thing
            // on every run.
            let mut rules: Vec<(String, usize)> = Vec::new();
            let mut extra: Vec<Vec<crate::forward::Forwarder>> = Vec::new();
            for (pattern, servers) in &dns.nameserver_policy {
                if servers.is_empty() {
                    return Err(Error::config(format!(
                        "dns.nameserver-policy entry {pattern:?} lists no servers"
                    )));
                }
                let group = servers
                    .iter()
                    .map(|s| parse_upstream(s))
                    .collect::<Result<Vec<_>>>()?;
                rules.push((pattern.clone(), 2 + extra.len()));
                extra.push(group);
            }
            let policy = crate::routing::NameserverPolicy::new(&rules)?;
            (
                crate::resolver::UpstreamGroups {
                    default,
                    fallback,
                    extra,
                },
                policy,
            )
        };
        #[cfg(not(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq")))]
        let policy = {
            if !dns.nameservers.is_empty()
                || !dns.fallback.is_empty()
                || !dns.nameserver_policy.is_empty()
            {
                return Err(Error::config(
                    "dns.nameservers / dns.fallback / dns.nameserver-policy require a build \
                     with the dot, doh, doh3 or doq feature",
                ));
            }
            crate::routing::NameserverPolicy::default()
        };

        Ok(crate::resolver::DnsPolicy {
            hosts,
            fake_ip,
            policy,
            fallback,
            #[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
            upstreams,
        })
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
            query_budget_ms: engine
                .query_budget_ms
                .unwrap_or(d.engine.query_budget_ms),
            auth_port: engine.auth_port.unwrap_or(d.engine.auth_port),
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
            dns: self.build_dns_policy()?,
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

    /// The query budget is a different bound from the per-attempt timeout, so
    /// it needs to be settable — and all three spellings of the key must be
    /// accepted, because the struct denies unknown keys and a user who guesses
    /// the other convention would otherwise get a hard parse error.
    #[test]
    fn query_budget_is_configurable_in_three_spellings() {
        for key in ["queryBudgetMs", "query_budget_ms", "query-budget-ms"] {
            let json = alloc::format!(r#"{{"engine":{{"{key}":5000}}}}"#);
            let rc = Config::from_json_str(&json)
                .unwrap_or_else(|e| panic!("{key} was rejected: {e}"))
                .into_resolver_config()
                .unwrap();
            assert_eq!(rc.engine.query_budget_ms, 5000, "for {key}");
        }
        // Absent means the default, and the default is finite.
        let rc = Config::from_json_str(r#"{"listen":[]}"#)
            .unwrap()
            .into_resolver_config()
            .unwrap();
        assert_eq!(rc.engine.query_budget_ms, EngineConfig::default().query_budget_ms);
        assert!(rc.engine.query_budget_ms > 0);
    }

    #[test]
    fn rr_type_parsing() {
        assert_eq!(parse_rr_type("A"), Some(RrType::A));
        assert_eq!(parse_rr_type("https"), Some(RrType::HTTPS));
        assert_eq!(parse_rr_type("TYPE1234"), Some(RrType(1234)));
        assert_eq!(parse_rr_type("NOPE"), None);
    }

    /// Tests for the Clash-compatible `dns` section. Split out because the
    /// upstream-string forms only exist when an encrypted transport is
    /// compiled in.
    #[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
    mod dns_section {
        use super::*;
        use crate::name::Name;
        use crate::routing::Route;

        fn n(s: &str) -> Name {
            Name::from_ascii(s).unwrap()
        }

        /// Every Clash spelling of a multi-word key is accepted. This is the
        /// guard for the failure this section exists to fix: a key that
        /// parses into nothing.
        #[test]
        fn clash_kebab_and_snake_keys_are_accepted() {
            for key in ["nameserver-policy", "nameserver_policy", "nameserverPolicy"] {
                let json = format!(
                    r#"{{"dns": {{"{key}": {{"+.node.example": ["tls://10.0.0.53#dns.example"]}}}}}}"#
                );
                let rc = Config::from_json_str(&json)
                    .unwrap_or_else(|e| panic!("{key} should parse: {e}"))
                    .into_resolver_config()
                    .unwrap();
                assert_eq!(rc.dns.policy.len(), 1, "{key} produced no rule");
            }
            for key in ["fallback-filter", "fallback_filter", "fallbackFilter"] {
                let json = format!(r#"{{"dns": {{"{key}": {{"ipcidr": ["10.0.0.0/8"]}}}}}}"#);
                let rc = Config::from_json_str(&json)
                    .unwrap_or_else(|e| panic!("{key} should parse: {e}"))
                    .into_resolver_config()
                    .unwrap();
                assert_eq!(
                    rc.dns.fallback.ipcidr().len(),
                    1,
                    "{key} produced no blocks"
                );
            }
        }

        /// An unknown key is refused *and named*. Silently dropping it is the
        /// whole bug class being fixed here.
        #[test]
        fn unknown_keys_are_refused_not_dropped() {
            let e = Config::from_json_str(
                r#"{"dns": {"nameserver-policyy": {"+.a.com": ["tls://1.1.1.1#a.b"]}}}"#,
            )
            .unwrap_err();
            assert!(e.msg.contains("nameserver-policyy"), "{}", e.msg);

            let e = Config::from_json_str(r#"{"dnss": {}}"#).unwrap_err();
            assert!(e.msg.contains("dnss"), "{}", e.msg);

            // The same inside `engine`, where the old silent drop lived.
            let e = Config::from_json_str(r#"{"engine": {"timeoutMsX": 5}}"#).unwrap_err();
            assert!(e.msg.contains("timeoutMsX"), "{}", e.msg);
        }

        /// All three fake-IP spellings turn the mode on; the two off states
        /// stay off; a typo is an error, not a silent `normal`.
        #[test]
        fn enhanced_mode_accepts_clash_spellings() {
            for (key, val) in [
                ("enhanced-mode", "fake-ip"),
                ("enhanced_mode", "fake-ip"),
                ("enhancedMode", "fakeip"),
            ] {
                let json = format!(r#"{{"dns": {{"{key}": "{val}"}}}}"#);
                let rc = Config::from_json_str(&json)
                    .unwrap()
                    .into_resolver_config()
                    .unwrap();
                assert!(
                    rc.dns.fake_ip_enabled(),
                    "{key}={val} did not enable fake-ip"
                );
            }
            for val in ["normal", "redir-host"] {
                let json = format!(r#"{{"dns": {{"enhanced-mode": "{val}"}}}}"#);
                let rc = Config::from_json_str(&json)
                    .unwrap()
                    .into_resolver_config()
                    .unwrap();
                assert!(!rc.dns.fake_ip_enabled(), "{val} must not enable fake-ip");
            }
            let e = Config::from_json_str(r#"{"dns":{"enhanced-mode":"fakeipx"}}"#)
                .unwrap()
                .into_resolver_config()
                .unwrap_err();
            assert!(e.msg.contains("fake-ip"), "{}", e.msg);
        }

        /// `fake-ip-range6` accepts all three spellings, and its presence is
        /// what turns `AAAA` synthesis on. Absent means IPv6 stays NODATA,
        /// which is the pre-existing behaviour.
        #[test]
        fn fake_ip_range6_is_opt_in_and_spelled_three_ways() {
            use crate::fakeip::Family;
            for key in ["fake-ip-range6", "fake_ip_range6", "fakeIpRange6"] {
                let json = format!(
                    r#"{{"dns": {{"enhanced-mode": "fake-ip", "{key}": "fdfe:dcba:9876::/48"}}}}"#
                );
                let rc = Config::from_json_str(&json)
                    .unwrap_or_else(|e| panic!("{key} should parse: {e}"))
                    .into_resolver_config()
                    .unwrap();
                let s = rc.dns.fake_ip.as_ref().expect("fake-ip mode is on");
                assert_eq!(
                    s.range6.expect("range6 must be set").to_string(),
                    "fdfe:dcba:9876::/48",
                    "{key}"
                );
                assert!(s.synthesizes(Family::V6), "{key} must enable v6 synthesis");
                assert!(s.synthesizes(Family::V4), "v4 stays on");
            }

            // Absent: v4 only.
            let rc = Config::from_json_str(r#"{"dns": {"enhanced-mode": "fake-ip"}}"#)
                .unwrap()
                .into_resolver_config()
                .unwrap();
            let s = rc.dns.fake_ip.as_ref().unwrap();
            assert!(s.range6.is_none());
            assert!(!s.synthesizes(Family::V6));
            assert!(s.synthesizes(Family::V4));

            // A malformed v6 range is refused by name, not ignored.
            let e = Config::from_json_str(
                r#"{"dns": {"enhanced-mode": "fake-ip", "fake-ip-range6": "198.18.0.0/16"}}"#,
            )
            .unwrap()
            .into_resolver_config()
            .unwrap_err();
            assert!(e.msg.contains("range6"), "{}", e.msg);
        }

        /// `hosts` accepts both a bare string and a list, and both are
        /// enforced — including the NODATA-for-the-other-family rule.
        #[test]
        fn hosts_accepts_string_and_list() {
            let rc = Config::from_json_str(
                r#"{"dns": {"hosts": {
                    "one.example": "10.0.0.1",
                    "many.example": ["10.0.0.2", "2001:db8::2"]
                }}}"#,
            )
            .unwrap()
            .into_resolver_config()
            .unwrap();
            assert_eq!(rc.dns.hosts.len(), 2);
            assert_eq!(
                rc.dns
                    .hosts
                    .answer(&n("one.example"), RrType::A)
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                rc.dns
                    .hosts
                    .answer(&n("many.example"), RrType::A)
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                rc.dns
                    .hosts
                    .answer(&n("many.example"), RrType::AAAA)
                    .unwrap()
                    .len(),
                1
            );
            // A v4-only pin answers AAAA with an empty answer: NODATA by
            // decision, not a miss.
            assert!(rc
                .dns
                .hosts
                .answer(&n("one.example"), RrType::AAAA)
                .unwrap()
                .is_empty());
        }

        /// Naming the upstreams twice is refused rather than resolved in one
        /// list's favour.
        #[test]
        fn duplicate_upstream_configuration_is_refused() {
            let e = Config::from_json_str(
                r#"{
                    "dns": {"nameservers": ["8.8.8.8"]},
                    "engine": {"forwarders": [{"ip": "1.1.1.1", "proto": "udp"}]}
                }"#,
            )
            .unwrap()
            .into_resolver_config()
            .unwrap_err();
            assert!(e.msg.contains("not both"), "{}", e.msg);
        }

        /// `geoip` and `geoipCode` are refused with the replacements named,
        /// because accepting either would leave an anti-pollution config with
        /// no anti-pollution.
        #[test]
        fn geoip_settings_are_refused_loudly() {
            let e = Config::from_json_str(r#"{"dns":{"fallback-filter":{"geoip":true}}}"#)
                .unwrap()
                .into_resolver_config()
                .unwrap_err();
            assert!(e.msg.contains("geoip"), "{}", e.msg);
            assert!(e.msg.contains("ipcidr"), "{}", e.msg);

            let e = Config::from_json_str(r#"{"dns":{"fallback-filter":{"geoipCode":["CN"]}}}"#)
                .unwrap()
                .into_resolver_config()
                .unwrap_err();
            assert!(e.msg.contains("geoipCode"), "{}", e.msg);
        }

        /// A bad upstream string is refused with the reason, never accepted
        /// as an endpoint that cannot work.
        #[test]
        fn bad_upstream_strings_are_refused() {
            for (s, want) in [
                ("tls://dns.google#x", "IP literal"),
                ("tls://1.1.1.1", "TLS name"),
                ("ftp://1.1.1.1", "unknown scheme"),
                ("udp://1.1.1.1#x", "no TLS identity"),
                ("tls://1.1.1.1/dns-query#x", "takes no path"),
            ] {
                let json = format!(r#"{{"dns": {{"nameservers": ["{s}"]}}}}"#);
                let e = Config::from_json_str(&json)
                    .unwrap()
                    .into_resolver_config()
                    .unwrap_err();
                assert!(e.msg.contains(want), "{s} => {} (wanted {want:?})", e.msg);
            }
        }

        /// Upstream strings parse into the right transport, port, identity
        /// and path.
        #[test]
        fn upstream_strings_parse() {
            let f = parse_upstream("8.8.8.8").unwrap();
            assert_eq!(f.endpoint.proto, Proto::Udp);
            assert_eq!(f.endpoint.port, 53);
            assert!(f.host.is_none());

            let f = parse_upstream("tcp://8.8.8.8:5353").unwrap();
            assert_eq!(f.endpoint.proto, Proto::Tcp);
            assert_eq!(f.endpoint.port, 5353);

            let f = parse_upstream("tls://1.1.1.1#one.one.one.one").unwrap();
            assert_eq!(f.endpoint.proto, Proto::Tls);
            assert_eq!(f.endpoint.port, 853);
            assert_eq!(f.host.as_deref(), Some("one.one.one.one"));

            let f = parse_upstream("https://1.1.1.1/dns-query#cloudflare-dns.com").unwrap();
            assert_eq!(f.endpoint.proto, Proto::DoH);
            assert_eq!(f.endpoint.port, 443);
            assert_eq!(f.doh_path(), "/dns-query");

            // An absent path means the RFC 8484 default.
            let f = parse_upstream("https://1.1.1.1#cloudflare-dns.com").unwrap();
            assert_eq!(f.doh_path(), "/dns-query");

            // Bracketed IPv6 with an explicit port, over DoT.
            let f = parse_upstream("tls://[2001:db8::1]:8853#dns.example").unwrap();
            assert_eq!(f.endpoint.proto, Proto::Tls);
            assert_eq!(f.endpoint.port, 8853);
            assert!(f.endpoint.ip.is_ipv6());

            // A scheme-less address is UDP, so it must not carry a TLS name.
            let f = parse_upstream("1.1.1.1").unwrap();
            assert_eq!(f.endpoint.proto, Proto::Udp);
            assert!(f.host.is_none());

            let f = parse_upstream("quic://[2001:db8::1]#dns.example").unwrap();
            assert_eq!(f.endpoint.proto, Proto::DoQ);
            assert_eq!(f.endpoint.port, 853);

            // Unbound's `@port` spelling, so a forwarder line copied from an
            // Unbound config keeps working.
            let f = parse_upstream("1.1.1.1@5353").unwrap();
            assert_eq!(f.endpoint.proto, Proto::Udp);
            assert_eq!(f.endpoint.port, 5353);

            let f = parse_upstream("tls://1.1.1.1@853#cloudflare-dns.com").unwrap();
            assert_eq!(f.endpoint.proto, Proto::Tls);
            assert_eq!(f.endpoint.port, 853);
            assert_eq!(f.host.as_deref(), Some("cloudflare-dns.com"));

            let f = parse_upstream("tls://[2001:db8::1]@853#dns.example").unwrap();
            assert_eq!(f.endpoint.proto, Proto::Tls);
            assert_eq!(f.endpoint.port, 853);

            // An `@` with something that is not a port is still a mistake.
            assert!(parse_upstream("1.1.1.1@nope").is_err());
        }

        /// The policy routes, and the filter is wired rather than stored.
        #[test]
        fn nameserver_policy_and_filter_are_wired() {
            let rc = Config::from_json_str(
                r#"{
                    "dns": {
                        "nameservers": ["tls://1.1.1.1#one.one.one.one"],
                        "fallback": ["tls://8.8.8.8#dns.google"],
                        "nameserver-policy": {
                            "+.node.example": ["tls://10.0.0.53#dns.example"]
                        },
                        "fallback-filter": {
                            "ipcidr": ["198.18.0.0/15"],
                            "domain": ["+.polluted.example"]
                        }
                    }
                }"#,
            )
            .unwrap()
            .into_resolver_config()
            .unwrap();
            let dns = &rc.dns;

            // Suffix routing: the node domain reaches its own group, a
            // neighbour does not.
            assert_ne!(dns.policy.route(&n("n1.node.example")), Route::Default);
            assert_eq!(dns.policy.route(&n("other.test")), Route::Default);

            // The forced-fallback list and the pollution blocks are live.
            assert!(dns.fallback.forces_fallback(&n("www.polluted.example")));
            assert!(dns
                .fallback
                .looks_poisoned(&["198.18.0.7".parse().unwrap()])
                .is_some());
            // The operator's list replaced the built-ins.
            assert!(dns
                .fallback
                .looks_poisoned(&["0.0.0.0".parse().unwrap()])
                .is_none());
        }

        /// The legacy spelling keeps working, and populates the default group
        /// so one routing path serves both.
        #[test]
        fn legacy_engine_forwarders_become_the_default_group() {
            let rc = Config::from_json_str(
                r#"{"engine": {"forwarders": [
                    {"ip": "1.1.1.1", "port": 0, "proto": "udp"}
                ]}}"#,
            )
            .unwrap()
            .into_resolver_config()
            .unwrap();
            assert_eq!(rc.dns.upstreams.default.len(), 1);
            assert!(rc.dns.policy.is_empty());
            assert!(!rc.dns.upstreams.has_fallback());
        }
    }

    /// With no `dns` section at all, the layer is inert: the pre-existing
    /// behaviour, unchanged. This is the property that makes the whole
    /// section safe to add.
    #[test]
    fn absent_dns_section_changes_nothing() {
        let rc = Config::from_json_str(r#"{"listen":[]}"#)
            .unwrap()
            .into_resolver_config()
            .unwrap();
        assert!(rc.dns.is_default());
        assert!(!rc.dns.fake_ip_enabled());
        assert!(rc.dns.hosts.is_empty());
        assert!(rc.dns.policy.is_empty());
    }
}
