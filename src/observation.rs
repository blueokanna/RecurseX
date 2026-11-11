//! Opt-in, bounded in-memory observations of completed resolver calls.
//!
//! This is not a packet capture: engine lookups and loopback resolver calls
//! are separate operations. No callback runs on a resolver worker. Contention
//! drops an observation rather than delaying an answer, and is counted.

use crate::{query::QueryKey, sync::Mutex, Resolution, Result};
use std::collections::VecDeque;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// One completed resolver call. Answers are bounded display summaries.
#[derive(Clone, Debug)]
pub struct QueryEvent {
    /// Monotonic event identifier within this process.
    pub id: u64,
    /// Completion time, milliseconds since the Unix epoch.
    pub completed_at_ms: u64,
    /// Queried domain, in DNS presentation form.
    pub name: String,
    /// Query type, including unknown numeric types.
    pub rr_type: String,
    /// Configured resolution path: forwarding or recursion.
    pub path: String,
    /// Actual answer summaries, at most eight, each at most 256 bytes.
    pub answers: Vec<String>,
    /// Response code or stable error category.
    pub outcome: String,
    /// Whether the result was served from the resolver's cache.
    pub from_cache: bool,
    /// Whether expired data was served under the stale policy.
    pub stale: bool,
    /// Time spent in this call, including coalescing and retries.
    pub elapsed_us: u64,
    /// True if the display summary omits records or bytes.
    pub truncated: bool,
}

/// Snapshot of retained observations; counters reset when collection is reset.
#[derive(Clone, Debug)]
pub struct QuerySnapshot {
    /// Oldest to newest retained events.
    pub events: Vec<QueryEvent>,
    /// Completed observations since reset, including dropped events.
    pub total: u64,
    /// Observations dropped because the buffer was being read or written.
    pub dropped: u64,
}

static CAPACITY: AtomicUsize = AtomicUsize::new(0);
static SEQUENCE: AtomicU64 = AtomicU64::new(1);
static TOTAL: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static EVENTS: Mutex<VecDeque<QueryEvent>> = Mutex::new(VecDeque::new());

/// Enable collection with a capacity of 1..=512, or disable it with zero.
/// Clears retained names and counters. No query history is persisted.
pub fn configure(capacity: usize) {
    let mut events = EVENTS.lock();
    CAPACITY.store(capacity.min(512), Ordering::Release);
    events.clear();
    TOTAL.store(0, Ordering::Relaxed);
    DROPPED.store(0, Ordering::Relaxed);
}

/// Copy a bounded snapshot. Does not drain it, so multiple views can read it.
pub fn snapshot() -> QuerySnapshot {
    QuerySnapshot {
        events: EVENTS.lock().iter().cloned().collect(),
        total: TOTAL.load(Ordering::Relaxed),
        dropped: DROPPED.load(Ordering::Relaxed),
    }
}

struct Summary {
    text: String,
    truncated: bool,
}

impl std::fmt::Write for Summary {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        let available = 256usize.saturating_sub(self.text.len());
        let mut end = available.min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        if let Some(part) = text.get(..end) {
            self.text.push_str(part);
        }
        self.truncated |= end < text.len();
        Ok(())
    }
}

pub(crate) fn record(key: &QueryKey, path: &str, result: &Result<Resolution>, elapsed: Duration) {
    if CAPACITY.load(Ordering::Acquire) == 0 {
        return;
    }
    TOTAL.fetch_add(1, Ordering::Relaxed);
    let Some(mut events) = EVENTS.try_lock() else {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let capacity = CAPACITY.load(Ordering::Acquire);
    if capacity == 0 {
        return;
    }
    let mut event = QueryEvent {
        id: SEQUENCE.fetch_add(1, Ordering::Relaxed),
        completed_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64,
        name: key.name.to_ascii(),
        rr_type: key.rr_type.to_string(),
        path: path.into(),
        answers: Vec::new(),
        outcome: String::new(),
        from_cache: false,
        stale: false,
        elapsed_us: elapsed.as_micros().min(u64::MAX as u128) as u64,
        truncated: false,
    };
    match result {
        Ok(res) => {
            event.outcome = res.rcode.to_string();
            event.from_cache = res.from_cache;
            event.stale = res.stale;
            event.truncated = res.answers.len() > 8;
            for record in res.answers.iter().take(8) {
                let mut summary = Summary {
                    text: String::new(),
                    truncated: false,
                };
                match &record.rdata {
                    crate::RData::A(ip) => {
                        let _ = write!(summary, "{ip}");
                    }
                    crate::RData::Aaaa(ip) => {
                        let _ = write!(summary, "{ip}");
                    }
                    data => {
                        let _ = write!(summary, "{data:?}");
                    }
                }
                event.truncated |= summary.truncated;
                event.answers.push(summary.text);
            }
        }
        Err(error) => event.outcome = format!("{:?}", error.kind),
    }
    while events.len() >= capacity {
        events.pop_front();
    }
    events.push_back(event);
}
