//! # RecurseX — a predictive adaptive recursive DNS resolver
//!
//! The crate is organized as a pipeline: a client-facing layer, a query
//! processing layer, a multi-tier semantic cache, a recursive resolution
//! engine, upstream transports, and a security/policy layer. The
//! algorithmic cores (wire codec, cache, estimator, alias graph, upstream
//! model) are `no_std`; the networked resolver requires the `std` feature.
//!
//! ## Resolving
//!
//! The wire codec needs no network and no `std`:
//!
//! ```
//! use recurse_x::{Message, Name, RrType};
//!
//! let query = Message::query(0x1234, Name::from_ascii("www.example.com")?, RrType::A, true);
//! let bytes = query.to_bytes()?;
//! assert_eq!(Message::parse(&bytes)?, query);
//! # Ok::<(), recurse_x::Error>(())
//! ```
//!
//! A resolver is built from a [`ResolverConfig`], most commonly parsed from
//! a JSON document:
//!
//! ```
//! # #[cfg(feature = "std")]
//! # {
//! use recurse_x::config::Config;
//! use recurse_x::Resolver;
//!
//! let json = r#"{
//!     "cache": { "hotCapacity": 256 },
//!     "engine": { "qnameMinimization": true }
//! }"#;
//! let resolver = Resolver::new(Config::from_json_str(json)?.into_resolver_config()?);
//! assert_eq!(resolver.stats_snapshot().queries, 0);
//! # }
//! # Ok::<(), recurse_x::Error>(())
//! ```
//!
//! Serving clients needs a [`Server`] around the resolver; both stop on
//! request and `join` returns once every loop has exited:
//!
//! ```
//! # #[cfg(feature = "std")]
//! # {
//! use recurse_x::{Resolver, ResolverConfig, Server};
//!
//! let resolver = Resolver::new(ResolverConfig::default());
//! let server = Server::new(resolver.clone());
//! let addr = server.bind_udp("127.0.0.1:0".parse().unwrap())?;
//! assert_ne!(addr.port(), 0);
//! server.shutdown();
//! resolver.shutdown();
//! server.join();
//! # }
//! # Ok::<(), recurse_x::Error>(())
//! ```
//!
//! [`Config`]: config::Config
//! [`Server`]: server::Server

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(missing_debug_implementations)]
#![deny(clippy::todo, clippy::unimplemented, clippy::dbg_macro)]
#![warn(missing_docs)]
#![allow(clippy::needless_return)]

extern crate alloc;

pub mod alias;
pub mod bounded;
pub mod cache;
pub mod cidr;
pub mod edns;
pub mod engine;
pub mod error;
pub mod estimator;
pub mod fakeip;
pub mod float;
pub mod hosts;
pub mod message;
pub mod name;
pub mod pattern;
pub mod planner;
pub mod policy;
pub mod prng;
pub mod qtype;
pub mod query;
pub mod rdata;
pub mod routing;
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
