//! Shared DNS work envelopes, charged at the exchange boundary.
//!
//! Byte accounting covers DNS payloads, not IP/TLS/HTTP framing or unsolicited
//! traffic. A maximum DNS response is reserved before each send; failed
//! exchanges retain that reservation because received bytes may be unknown.
//! A scoped thread context shares foreground limits across nested DNSSEC and
//! forwarder exchanges; background scopes additionally charge a global budget.

use crate::budget::{FetchLimits, Work};
use crate::error::{Error, ErrorKind, Result};
use crate::sync::Mutex;
use crate::upstream::Endpoint;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const RESPONSE_RESERVE: u64 = 65_535;

/// Exchange attempts and known DNS payload bytes for replay diagnostics.
#[derive(Debug, Default)]
pub struct ExchangeCounters {
    attempts: AtomicU64,
    bytes: AtomicU64,
}

impl ExchangeCounters {
    /// Attempts and sent/returned DNS bytes. Failed handshakes are attempts;
    /// partial reads and transport framing require external packet capture.
    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.attempts.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
        )
    }
}

thread_local! { static COUNTERS: RefCell<Option<Arc<ExchangeCounters>>> = const { RefCell::new(None) }; }
pub(crate) struct ExchangeScope(Option<Arc<ExchangeCounters>>);
impl ExchangeScope {
    pub(crate) fn enter(counters: Arc<ExchangeCounters>) -> Self {
        Self(COUNTERS.with(|slot| slot.replace(Some(counters))))
    }
}
impl Drop for ExchangeScope {
    fn drop(&mut self) {
        COUNTERS.with(|slot| slot.replace(self.0.take()));
    }
}

/// Limits for each monotonic one-second accounting window.
#[derive(Clone, Copy, Debug)]
pub struct BackgroundLimits {
    /// Upstream exchanges across all background tasks per window.
    pub exchanges_per_second: u64,
    /// DNS payload bytes, including outstanding response reservations.
    pub bytes_per_second: u64,
    /// Concurrent exchanges to one server IP, across ports/protocols.
    pub per_authority_concurrency: usize,
    /// Exchanges to one server IP per window.
    pub per_authority_per_second: u64,
    /// Hard cap on tracked server IPs; a full active table refuses new IPs.
    pub max_authorities: usize,
}

impl Default for BackgroundLimits {
    fn default() -> Self {
        Self {
            exchanges_per_second: 256,
            bytes_per_second: 8 << 20,
            per_authority_concurrency: 2,
            per_authority_per_second: 32,
            max_authorities: 1024,
        }
    }
}

#[derive(Debug, Default)]
struct Authority {
    active: usize,
    requests: u64,
}

#[derive(Debug)]
struct State {
    epoch: Instant,
    requests: u64,
    bytes: u64,
    authorities: BTreeMap<IpAddr, Authority>,
    observed: Work,
    denied: u64,
}

/// Resolver-wide budget shared by its fixed background worker pool.
#[derive(Debug)]
pub struct BackgroundBudget {
    limits: BackgroundLimits,
    state: Mutex<State>,
}

impl BackgroundBudget {
    /// Start with an unused budget.
    pub fn new(limits: BackgroundLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(State {
                epoch: Instant::now(),
                requests: 0,
                bytes: 0,
                authorities: BTreeMap::new(),
                observed: Work::default(),
                denied: 0,
            }),
        }
    }

    /// Completed/attempted DNS work and denied sends (never resets).
    pub fn snapshot(&self) -> (Work, u64) {
        let state = self.state.lock();
        (state.observed, state.denied)
    }

    fn reserve(self: &Arc<Self>, ip: IpAddr, query_bytes: u64) -> Result<Permit> {
        let mut state = self.state.lock();
        if state.epoch.elapsed() >= Duration::from_secs(1) {
            state.epoch = Instant::now();
            state.requests = 0;
            state.bytes = 0;
            // Active exchanges retain a response reservation in the new window.
            state.authorities.retain(|_, a| a.active > 0);
            let active: usize = state.authorities.values().map(|a| a.active).sum();
            state.bytes = (active as u64).saturating_mul(RESPONSE_RESERVE);
            for authority in state.authorities.values_mut() {
                authority.requests = 0;
            }
        }
        let cost = query_bytes.saturating_add(RESPONSE_RESERVE);
        let authority_ok = state.authorities.get(&ip).map_or(
            state.authorities.len() < self.limits.max_authorities,
            |a| {
                a.active < self.limits.per_authority_concurrency
                    && a.requests < self.limits.per_authority_per_second
            },
        );
        if self.limits.per_authority_concurrency == 0
            || self.limits.per_authority_per_second == 0
            || !authority_ok
            || state.requests >= self.limits.exchanges_per_second
            || state.bytes.saturating_add(cost) > self.limits.bytes_per_second
        {
            state.denied = state.denied.saturating_add(1);
            return Err(Error::new(
                ErrorKind::RateLimited,
                "background exchange budget exhausted",
            ));
        }
        state.requests += 1;
        state.bytes += cost;
        state.observed.subqueries = state.observed.subqueries.saturating_add(1);
        state.observed.bytes = state.observed.bytes.saturating_add(query_bytes);
        let authority = state.authorities.entry(ip).or_default();
        authority.active += 1;
        authority.requests += 1;
        Ok(Permit {
            budget: self.clone(),
            ip,
            received: None,
        })
    }
}

struct Permit {
    budget: Arc<BackgroundBudget>,
    ip: IpAddr,
    received: Option<u64>,
}
impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self.budget.state.lock();
        if let Some(received) = self.received {
            state.bytes = state
                .bytes
                .saturating_sub(RESPONSE_RESERVE.saturating_sub(received));
            state.observed.bytes = state.observed.bytes.saturating_add(received);
        }
        if let Some(authority) = state.authorities.get_mut(&self.ip) {
            authority.active -= 1;
        }
    }
}

struct TaskContext {
    budget: Option<Arc<BackgroundBudget>>,
    limits: FetchLimits,
    work: Work,
    reserved_bytes: u64,
    deadline: Instant,
}
thread_local! { static TASK: RefCell<Option<TaskContext>> = const { RefCell::new(None) }; }

pub(crate) fn task_deadline() -> Option<Instant> {
    TASK.with(|task| task.borrow().as_ref().map(|task| task.deadline))
}

pub(crate) struct TaskScope {
    previous: Option<TaskContext>,
}
impl TaskScope {
    /// Nested DNSKEY/DS work shares its caller's envelope and deadline.
    pub(crate) fn enter_query(limits: FetchLimits, timeout_ms: u64) -> Option<Self> {
        if TASK.with(|task| task.borrow().is_some()) {
            return None;
        }
        Some(Self::enter_inner(None, limits, timeout_ms))
    }

    pub(crate) fn enter(
        budget: Arc<BackgroundBudget>,
        limits: FetchLimits,
        timeout_ms: u64,
    ) -> Self {
        Self::enter_inner(Some(budget), limits, timeout_ms)
    }

    fn enter_inner(
        budget: Option<Arc<BackgroundBudget>>,
        limits: FetchLimits,
        timeout_ms: u64,
    ) -> Self {
        let context = TaskContext {
            budget,
            limits,
            work: Work::default(),
            reserved_bytes: 0,
            deadline: Instant::now()
                .checked_add(Duration::from_millis(timeout_ms))
                .unwrap_or_else(Instant::now),
        };
        Self {
            previous: TASK.with(|task| task.replace(Some(context))),
        }
    }
    pub(crate) fn work(&self) -> Work {
        TASK.with(|task| task.borrow().as_ref().map_or(Work::default(), |t| t.work))
    }
}
impl Drop for TaskScope {
    fn drop(&mut self) {
        TASK.with(|task| task.replace(self.previous.take()));
    }
}

/// All resolver transport dispatch goes through this boundary. Foreground
/// exchanges without a background scope retain their existing behavior.
pub(crate) fn exchange(
    endpoint: &Endpoint,
    query_bytes: usize,
    timeout_ms: u64,
    send: impl FnOnce(u64) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    let send = |timeout| {
        let counters = COUNTERS.with(|slot| slot.borrow().clone());
        if let Some(counters) = &counters {
            counters.attempts.fetch_add(1, Ordering::Relaxed);
            counters
                .bytes
                .fetch_add(query_bytes as u64, Ordering::Relaxed);
        }
        let result = send(timeout);
        if let (Some(counters), Ok(bytes)) = (counters, &result) {
            counters
                .bytes
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        }
        result
    };
    let admission = TASK.with(|task| -> Result<_> {
        let mut task = task.borrow_mut();
        let Some(task) = task.as_mut() else {
            return Ok(None);
        };
        let remaining = task
            .deadline
            .saturating_duration_since(Instant::now())
            .as_millis() as u64;
        if remaining == 0 {
            return Err(Error::new(
                ErrorKind::Timeout,
                "resolution task deadline exhausted",
            ));
        }
        let reserve = (query_bytes as u64).saturating_add(RESPONSE_RESERVE);
        if task.work.subqueries >= task.limits.max_subqueries
            || task.reserved_bytes.saturating_add(reserve) > task.limits.max_bytes
        {
            return Err(Error::new(
                ErrorKind::RateLimited,
                "resolution task work exhausted",
            ));
        }
        let permit = task
            .budget
            .as_ref()
            .map(|budget| budget.reserve(endpoint.ip, query_bytes as u64))
            .transpose()?;
        task.work.subqueries += 1;
        task.work.bytes = task.work.bytes.saturating_add(query_bytes as u64);
        task.reserved_bytes += reserve;
        Ok(Some((permit, timeout_ms.min(remaining).max(1))))
    })?;
    let Some((mut permit, timeout)) = admission else {
        return send(timeout_ms);
    };
    let result = send(timeout);
    if let Ok(bytes) = &result {
        if let Some(permit) = permit.as_mut() {
            permit.received = Some(bytes.len() as u64);
        }
        TASK.with(|task| {
            if let Some(task) = task.borrow_mut().as_mut() {
                task.work.bytes = task.work.bytes.saturating_add(bytes.len() as u64);
                task.reserved_bytes = task
                    .reserved_bytes
                    .saturating_sub(RESPONSE_RESERVE.saturating_sub(bytes.len() as u64));
            }
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_foreground_work_shares_one_envelope() {
        let scope = TaskScope::enter_query(
            FetchLimits {
                max_subqueries: 1,
                ..FetchLimits::default()
            },
            1000,
        )
        .unwrap();
        exchange(&endpoint(), 12, 100, |_| Ok(vec![0; 20])).unwrap();
        assert!(TaskScope::enter_query(FetchLimits::default(), 1000).is_none());
        assert!(exchange(&endpoint(), 12, 100, |_| panic!(
            "nested query must not escape the limit"
        ))
        .is_err());
        assert_eq!(scope.work().subqueries, 1);
        drop(scope);
        assert!(TaskScope::enter_query(FetchLimits::default(), 1000).is_some());
    }
    fn endpoint() -> Endpoint {
        Endpoint::udp("127.0.0.1".parse().unwrap())
    }
    #[test]
    fn work_exhaustion_refuses_before_the_next_send() {
        let budget = Arc::new(BackgroundBudget::new(BackgroundLimits {
            exchanges_per_second: 2,
            ..BackgroundLimits::default()
        }));
        let scope = TaskScope::enter(budget.clone(), FetchLimits::default(), 1000);
        for _ in 0..2 {
            exchange(&endpoint(), 12, 100, |_| Ok(vec![0; 20])).unwrap();
        }
        let mut sent = false;
        assert!(exchange(&endpoint(), 12, 100, |_| {
            sent = true;
            Ok(vec![])
        })
        .is_err());
        assert!(!sent);
        assert_eq!(scope.work().bytes, 64);
        assert_eq!(budget.snapshot().0.subqueries, 2);
    }
    #[test]
    fn bytes_and_authority_slots_are_reserved_before_sending() {
        let budget = Arc::new(BackgroundBudget::new(BackgroundLimits {
            bytes_per_second: RESPONSE_RESERVE + 12,
            per_authority_concurrency: 1,
            ..BackgroundLimits::default()
        }));
        let permit = budget.reserve(endpoint().ip, 12).unwrap();
        assert!(budget.reserve(endpoint().ip, 1).is_err());
        drop(permit); // Failure conservatively retains the byte reservation.
        assert!(budget.reserve(endpoint().ip, 1).is_err());
    }
    #[test]
    fn task_scope_resets_on_unwind_and_task_limit_is_independent() {
        let budget = Arc::new(BackgroundBudget::new(BackgroundLimits::default()));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _scope = TaskScope::enter(
                budget,
                FetchLimits {
                    max_subqueries: 0,
                    ..FetchLimits::default()
                },
                1000,
            );
            assert!(exchange(&endpoint(), 12, 100, |_| panic!("must not send")).is_err());
            panic!("task failure");
        }));
        assert!(exchange(&endpoint(), 12, 100, |_| Ok(vec![])).is_ok());
    }
    #[test]
    fn authority_table_and_concurrency_are_bounded() {
        let budget = Arc::new(BackgroundBudget::new(BackgroundLimits {
            max_authorities: 1,
            per_authority_concurrency: 1,
            ..BackgroundLimits::default()
        }));
        let mut first = budget.reserve(endpoint().ip, 12).unwrap();
        assert!(budget.reserve(endpoint().ip, 12).is_err());
        assert!(budget.reserve("127.0.0.2".parse().unwrap(), 12).is_err());
        first.received = Some(12);
        drop(first);
        assert!(budget.reserve(endpoint().ip, 12).is_ok());
    }
}
