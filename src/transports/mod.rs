//! Concrete upstream transports.

#[cfg(any(feature = "doh", feature = "doh3"))]
mod http_dns;
mod io;
pub mod tcp;
pub mod udp;
#[cfg(any(feature = "doh", feature = "doh3"))]
pub(crate) use http_dns::validate_endpoint as validate_http_endpoint;

#[cfg(feature = "doh")]
pub mod doh;
#[cfg(feature = "doh3")]
pub mod doh3;
#[cfg(feature = "doq")]
pub mod doq;
#[cfg(feature = "dot")]
pub mod dot;
