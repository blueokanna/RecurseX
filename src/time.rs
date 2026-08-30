//! Time model for the resolver.
//!
//! Wall time is carried as [`Ts`] (a signed 128-bit nanosecond count since
//! the Unix epoch — the same axis as `tzcraft::Ticks`). The resolver only
//! ever compares timestamps and adds TTLs to them, so a raw `i128` is the
//! right internal type: no overflow concerns for the next 292 billion
//! years, and `tzcraft` is used at the boundaries where wall-clock reading
//! (under `std`) and RFC 3339 rendering are needed.

#[cfg(feature = "std")]
use core::fmt;

/// Nanoseconds since the Unix epoch (matches `tzcraft::Ticks`'s axis).
pub type Ts = i128;

/// Nanoseconds per second.
pub const NS_PER_SEC: Ts = 1_000_000_000;
/// Nanoseconds per millisecond.
pub const NS_PER_MS: Ts = 1_000_000;

/// A clock source. The resolver holds one and queries it on every cache
/// lookup / admission decision. The system implementation requires `std`;
/// tests use a manual clock.
pub trait Clock: Send + Sync {
    /// The current wall-clock instant as nanoseconds since the epoch.
    fn now(&self) -> Ts;
}

/// The system clock (backed by `std::time::SystemTime`).
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

#[cfg(feature = "std")]
impl Clock for SystemClock {
    fn now(&self) -> Ts {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as Ts * NS_PER_SEC + d.subsec_nanos() as Ts)
            .unwrap_or(0)
    }
}

/// A manual clock for tests and deterministic simulation. Uses an interior
/// `RwLock` so it satisfies the `Clock` bounds.
#[cfg(feature = "std")]
#[derive(Debug, Default)]
pub struct ManualClock {
    now: std::sync::RwLock<Ts>,
}

#[cfg(feature = "std")]
impl ManualClock {
    /// A clock fixed at the Unix epoch.
    pub fn new() -> Self {
        Self::at(0)
    }

    /// A clock fixed at `secs` since the epoch.
    pub fn at_secs(secs: i64) -> Self {
        Self::at(secs as Ts * NS_PER_SEC)
    }

    /// A clock fixed at an arbitrary instant.
    pub fn at(ns: Ts) -> Self {
        Self {
            now: std::sync::RwLock::new(ns),
        }
    }

    /// Advance the clock.
    pub fn advance(&self, ns: Ts) {
        *self.now.write().unwrap() += ns;
    }

    /// Advance by whole seconds.
    pub fn advance_secs(&self, secs: i64) {
        self.advance(secs as Ts * NS_PER_SEC);
    }

    /// The current value.
    pub fn get(&self) -> Ts {
        *self.now.read().unwrap()
    }
}

#[cfg(feature = "std")]
impl Clock for ManualClock {
    fn now(&self) -> Ts {
        *self.now.read().unwrap()
    }
}

/// Add a number of seconds, saturating.
#[inline]
pub fn add_secs(t: Ts, secs: u32) -> Ts {
    t.saturating_add(secs as Ts * NS_PER_SEC)
}

/// Add a number of milliseconds, saturating.
#[inline]
pub fn add_ms(t: Ts, ms: u64) -> Ts {
    t.saturating_add(ms as Ts * NS_PER_MS)
}

/// Subtract a number of seconds, saturating.
#[inline]
pub fn sub_secs(t: Ts, secs: u32) -> Ts {
    t.saturating_sub(secs as Ts * NS_PER_SEC)
}

/// The remaining whole seconds from `now` until `deadline` (floor, never
/// negative).
#[inline]
pub fn remaining_secs(now: Ts, deadline: Ts) -> u32 {
    if deadline <= now {
        0
    } else {
        ((deadline - now) / NS_PER_SEC).min(u32::MAX as Ts) as u32
    }
}

/// Convert a timestamp to whole seconds (flooring).
#[inline]
pub fn to_secs(t: Ts) -> i64 {
    (t / NS_PER_SEC) as i64
}

/// Convert whole seconds to a timestamp.
#[inline]
pub fn from_secs(s: i64) -> Ts {
    s as Ts * NS_PER_SEC
}

/// Convert a timestamp to `tzcraft::Ticks` (same axis, zero cost).
#[inline]
pub fn to_ticks(t: Ts) -> tzcraft::Ticks {
    tzcraft::Ticks::from_unix_nanos(t)
}

/// Render a timestamp as an RFC 3339 UTC string.
#[cfg(any(feature = "std", test))]
pub fn format_rfc3339(t: Ts) -> String {
    use alloc::string::String;
    let mut buf = [0u8; 64];
    match to_ticks(t).write_rfc3339(&mut buf, tzcraft::FractionDigits::None) {
        Ok(n) => String::from_utf8_lossy(&buf[..n]).into_owned(),
        Err(_) => String::from("(invalid timestamp)"),
    }
}

#[cfg(feature = "std")]
impl fmt::Display for ManualClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ManualClock({})", *self.now.read().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_saturates() {
        let t = Ts::MAX;
        assert_eq!(add_secs(t, 10), t);
        assert_eq!(remaining_secs(Ts::MAX, Ts::MAX), 0);
        assert_eq!(remaining_secs(100, 200), 0);
        assert_eq!(remaining_secs(0, 5 * NS_PER_SEC), 5);
    }

    #[test]
    fn manual_clock_advances() {
        let c = ManualClock::at_secs(100);
        assert_eq!(c.now(), 100 * NS_PER_SEC);
        c.advance_secs(5);
        assert_eq!(c.get(), 105 * NS_PER_SEC);
    }

    #[test]
    fn rfc3339_formatting() {
        let s = format_rfc3339(0);
        assert_eq!(s, "1970-01-01T00:00:00Z");
    }
}
