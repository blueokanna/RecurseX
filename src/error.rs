//! Unified error type for the resolver.
//!
//! The error is a (kind, message) pair. The kind is a small, stable enum
//! that callers can match on; the message carries human-readable context.
//! Everything is `no_std + alloc` friendly; under `std` the error also
//! implements `std::error::Error` and converts from `std::io::Error`.

use alloc::string::String;
use core::fmt;

/// Stable error categories. New variants may be added; existing ones are
/// never renamed once released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// Malformed or hostile DNS wire data.
    Wire,
    /// A message was truncated (TC bit set or a read came up short).
    Truncated,
    /// A transport or resolution attempt timed out.
    Timeout,
    /// OS-level I/O failure.
    Io,
    /// Transport-level failure (TLS, HTTP status, QUIC error, framing).
    Transport,
    /// The authoritative server answered SERVFAIL.
    Servfail,
    /// The server answered REFUSED.
    Refused,
    /// The query resolved to an empty answer set (NODATA).
    NoData,
    /// The name does not exist (NXDOMAIN).
    NxDomain,
    /// DNSSEC validation failure.
    Dnssec,
    /// The request was dropped by a rate limiter.
    RateLimited,
    /// The request was rejected by a policy rule.
    Policy,
    /// No usable upstream could be reached.
    NoUpstream,
    /// Configuration error.
    Config,
    /// The operation was canceled (shutdown, coalesced request aborted).
    Canceled,
    /// An internal invariant was violated. Bugs live here.
    Internal,
    /// The requested capability is not compiled in or not supported.
    Unsupported,
}

/// A resolver error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// Stable category.
    pub kind: ErrorKind,
    /// Human-readable context.
    pub msg: String,
}

impl Error {
    /// Construct an error with a fixed category and message.
    pub fn new(kind: ErrorKind, msg: impl Into<String>) -> Self {
        Self {
            kind,
            msg: msg.into(),
        }
    }

    /// A malformed-wire error.
    pub fn wire(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Wire, msg)
    }

    /// An internal invariant violation.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal, msg)
    }

    /// A transport error.
    pub fn transport(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Transport, msg)
    }

    /// An I/O error.
    pub fn io(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Io, msg)
    }

    /// A configuration error.
    pub fn config(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Config, msg)
    }

    /// The stable category of this error.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Whether the error is transient (worth retrying).
    pub fn is_transient(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::Timeout | ErrorKind::Io | ErrorKind::Transport | ErrorKind::Servfail
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::io(e.to_string())
    }
}

/// Result alias for resolver operations.
pub type Result<T> = core::result::Result<T, Error>;
