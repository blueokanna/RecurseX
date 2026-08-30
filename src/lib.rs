//! # RecurseX — a predictive adaptive recursive DNS resolver
//!
//! The crate is organized as a pipeline: a client-facing layer, a query
//! processing layer, a multi-tier semantic cache, a recursive resolution
//! engine, upstream transports, and a security/policy layer. The
//! algorithmic cores (wire codec, cache, estimator, graph, upstream model)
//! are `no_std`; the networked resolver requires the `std` feature.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::needless_return)]

extern crate alloc;

pub mod cache;
pub mod edns;
pub mod engine;
pub mod error;
pub mod estimator;
pub mod float;
pub mod graph;
pub mod message;
pub mod name;
pub mod planner;
pub mod policy;
pub mod prng;
pub mod qtype;
pub mod query;
pub mod rdata;
pub mod rrset;
pub mod stability;
pub mod time;
pub mod upstream;

#[cfg(feature = "std")]
pub mod transport;
#[cfg(feature = "std")]
pub mod transports;

#[cfg(feature = "std")]
pub mod config;
#[cfg(feature = "dnssec")]
pub mod dnssec;
#[cfg(feature = "std")]
pub mod entropy;
#[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
pub mod forward;
#[cfg(feature = "std")]
pub mod resolver;
#[cfg(feature = "std")]
pub mod server;
#[cfg(feature = "std")]
pub mod stats;

#[cfg(feature = "std")]
pub use resolver::{Resolution, Resolver, ResolverConfig, SharedState};
#[cfg(feature = "std")]
pub use server::{Server, ServerConfig};

pub use error::{Error, ErrorKind, Result};
pub use message::{HeaderFlags, Message, Question};
pub use name::Name;
pub use qtype::{Opcode, Rcode, RrClass, RrType};
pub use rdata::{RData, Record};
