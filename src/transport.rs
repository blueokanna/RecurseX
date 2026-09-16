//! Upstream transports.
//!
//! A [`DnsTransport`] exchanges one query and returns one response as raw
//! bytes. The engine composes them: retries, server selection, fallback
//! from UDP to TCP, and the forwarders (DoT / DoH / DoH3 / DoQ).

use crate::error::Result;
use crate::transports::{tcp, udp};
use crate::upstream::{Endpoint, Proto};

/// Maximum UDP payload we accept (the EDNS buffer we advertise).
pub const MAX_UDP_PAYLOAD: usize = 4096;
/// Maximum DNS-over-TCP message size (2-byte length prefix).
pub const MAX_TCP_MESSAGE: usize = 65_535;

/// A single-query transport.
pub trait DnsTransport: Send + Sync {
    /// The wire protocol this transport speaks.
    fn proto(&self) -> Proto;

    /// Send `query` to `endpoint` and return the response bytes.
    /// `timeout_ms` bounds the whole exchange.
    fn exchange(&self, query: &[u8], endpoint: &Endpoint, timeout_ms: u64) -> Result<Vec<u8>>;
}

/// The set of transports available to the engine.
#[derive(Default)]
pub struct Transports {
    /// Plain UDP transport.
    pub udp: udp::UdpTransport,
    /// Plain TCP transport.
    pub tcp: tcp::TcpTransport,
    /// DNS-over-TLS transport (feature `dot`).
    #[cfg(feature = "dot")]
    pub dot: crate::transports::dot::DotTransport,
    /// DNS-over-HTTPS transport (feature `doh`).
    #[cfg(feature = "doh")]
    pub doh: crate::transports::doh::DohTransport,
    /// DNS-over-HTTP/3 transport (feature `doh3`).
    #[cfg(feature = "doh3")]
    pub doh3: crate::transports::doh3::Doh3Transport,
    /// DNS-over-QUIC transport (feature `doq`).
    #[cfg(feature = "doq")]
    pub doq: crate::transports::doq::DoqTransport,
}

/// Lists the protocols compiled into this build, which is the only thing
/// worth knowing about a transport set in a log line.
impl core::fmt::Debug for Transports {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Transports(udp, tcp")?;
        #[cfg(feature = "dot")]
        write!(f, ", dot")?;
        #[cfg(feature = "doh")]
        write!(f, ", doh")?;
        #[cfg(feature = "doh3")]
        write!(f, ", doh3")?;
        #[cfg(feature = "doq")]
        write!(f, ", doq")?;
        write!(f, ")")
    }
}

impl Transports {
    /// A default transport set (UDP + TCP always available under `std`).
    pub fn new() -> Self {
        Self {
            udp: udp::UdpTransport::default(),
            tcp: tcp::TcpTransport::default(),
            #[cfg(feature = "dot")]
            dot: crate::transports::dot::DotTransport::default(),
            #[cfg(feature = "doh")]
            doh: crate::transports::doh::DohTransport::default(),
            #[cfg(feature = "doh3")]
            doh3: crate::transports::doh3::Doh3Transport::default(),
            #[cfg(feature = "doq")]
            doq: crate::transports::doq::DoqTransport::default(),
        }
    }

    /// Exchange a query over the protocol of `endpoint`.
    pub fn exchange(&self, endpoint: &Endpoint, query: &[u8], timeout_ms: u64) -> Result<Vec<u8>> {
        match endpoint.proto {
            Proto::Udp => self.udp.exchange(query, endpoint, timeout_ms),
            Proto::Tcp => self.tcp.exchange(query, endpoint, timeout_ms),
            #[cfg(feature = "dot")]
            Proto::Tls => self.dot.exchange(query, endpoint, timeout_ms),
            #[cfg(feature = "doh")]
            Proto::DoH => self.doh.exchange(query, endpoint, timeout_ms),
            #[cfg(feature = "doh3")]
            Proto::DoH3 => self.doh3.exchange(query, endpoint, timeout_ms),
            #[cfg(feature = "doq")]
            Proto::DoQ => self.doq.exchange(query, endpoint, timeout_ms),
            #[cfg(not(feature = "dot"))]
            Proto::Tls => Err(crate::error::Error::new(
                crate::error::ErrorKind::Unsupported,
                "DoT transport not compiled in (enable the `dot` feature)",
            )),
            #[cfg(not(feature = "doh"))]
            Proto::DoH => Err(crate::error::Error::new(
                crate::error::ErrorKind::Unsupported,
                "DoH transport not compiled in (enable the `doh` feature)",
            )),
            #[cfg(not(feature = "doh3"))]
            Proto::DoH3 => Err(crate::error::Error::new(
                crate::error::ErrorKind::Unsupported,
                "DoH3 transport not compiled in (enable the `doh3` feature)",
            )),
            #[cfg(not(feature = "doq"))]
            Proto::DoQ => Err(crate::error::Error::new(
                crate::error::ErrorKind::Unsupported,
                "DoQ transport not compiled in (enable the `doq` feature)",
            )),
        }
    }
}
