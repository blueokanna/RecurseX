//! Forwarding disclosure limits. Encryption protects the path, not the resolver.

use crate::error::{Error, Result};

/// An explicit upper bound on which upstream IPs may observe one resolution.
/// Retries, fallback and nested DNSSEC fetches share the same allowance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpstreamPrivacy {
    /// Require certificate-verified encrypted forwarding; prohibit recursion.
    pub encrypted_only: bool,
    /// Permit two concurrent upstream attempts within the disclosure allowance.
    pub parallel: bool,
    /// Maximum distinct upstream IPs contacted, including unsuccessful attempts.
    /// This counts network destinations, not independently operated providers.
    pub max_upstreams: usize,
}

impl Default for UpstreamPrivacy {
    fn default() -> Self {
        Self {
            encrypted_only: false,
            parallel: true,
            max_upstreams: 32,
        }
    }
}

impl UpstreamPrivacy {
    /// One verified encrypted destination, no speculative duplicate, no ECS.
    /// The chosen resolver still sees the domain and the connection source IP.
    pub fn strict() -> Self {
        Self {
            encrypted_only: true,
            parallel: false,
            max_upstreams: 1,
        }
    }

    /// Reject unbounded or ineffective disclosure limits.
    pub fn validate(self) -> Result<()> {
        if !(1..=32).contains(&self.max_upstreams) {
            return Err(Error::config(
                "max-upstream-exposures must be between 1 and 32",
            ));
        }
        Ok(())
    }
}
