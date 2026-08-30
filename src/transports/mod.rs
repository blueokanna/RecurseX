//! Concrete upstream transports.

pub mod tcp;
pub mod udp;

#[cfg(feature = "doh")]
pub mod doh;
#[cfg(feature = "doh3")]
pub mod doh3;
#[cfg(feature = "doq")]
pub mod doq;
#[cfg(feature = "dot")]
pub mod dot;
