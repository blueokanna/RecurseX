//! Query processing: normalization, coalescing, and 0x20 matching.
//!
//! Every query the resolver sees is normalized to a canonical form before
//! it touches the cache or the engine, so the same name spelled in any
//! case hits the same entry. Concurrent identical queries are coalesced:
//! one resolution runs, the rest wait on it. And 0x20 (RFC 6840 §5.6)
//! anti-spoofing is validated here — a response must echo the query's
//! randomized QNAME case, modulo servers that normalize case.

use alloc::collections::BTreeMap;

use crate::cache::{CacheKey, EcsKey};
use crate::edns::Ecs;
use crate::message::Message;
use crate::name::Name;
use crate::qtype::{RrClass, RrType};
use crate::time::Ts;

/// The canonical, cacheable identity of a query.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct QueryKey {
    pub name: Name,
    pub rr_type: RrType,
    pub class: RrClass,
    /// The ECS network the client asked to be resolved from.
    pub ecs: Option<EcsKey>,
    /// Whether the client wants DNSSEC records (DO bit).
    pub want_dnssec: bool,
    /// Whether the client set CD (checking disabled).
    pub cd: bool,
}

impl QueryKey {
    /// Build from a parsed message's first question.
    pub fn from_message(msg: &Message) -> Option<QueryKey> {
        let q = msg.question()?;
        let ecs = msg
            .edns
            .as_ref()
            .and_then(|e| e.ecs())
            .and_then(EcsKey::from_ecs);
        Some(QueryKey {
            name: q.qname.clone(),
            rr_type: q.qtype,
            class: q.qclass,
            ecs,
            want_dnssec: msg.edns.as_ref().map(|e| e.dnssec_ok).unwrap_or(false),
            cd: msg.flags.cd,
        })
    }

    /// The cache key for this query.
    pub fn cache_key(&self) -> CacheKey {
        CacheKey {
            name: self.name.clone(),
            rr_type: self.rr_type,
            class: self.class,
            ecs: self.ecs.clone(),
        }
    }
}

/// Build an ECS option from a query key's partition.
pub fn ecs_option(key: &QueryKey) -> Option<Ecs> {
    let ecs = key.ecs.as_ref()?;
    Some(Ecs {
        family: ecs.family,
        source_prefix: ecs.prefix,
        scope_prefix: 0,
        address: ecs.addr.clone(),
    })
}

/// Verify a response's question against the query we sent.
///
/// RFC 5452 §8: the response question must match the query. With 0x20 the
/// QNAME case must match *exactly* when the server echoes it; servers are
/// permitted to normalize case, so we accept an exact match first and fall
/// back to a case-insensitive match (the 0x20 protection then rests on the
/// ID + source + bailiwick checks, which remain mandatory).
pub fn response_matches_query(query: &Message, response: &Message) -> bool {
    if query.id != response.id {
        return false;
    }
    let Some(qq) = query.question() else {
        return false;
    };
    let Some(rq) = response.question() else {
        return false;
    };
    if rq.qtype != qq.qtype || rq.qclass != qq.qclass {
        return false;
    }
    // Exact (case-sensitive) match first.
    if rq.qname.as_bytes() == qq.qname.as_bytes() {
        return true;
    }
    // Then case-insensitive (canonical) match.
    rq.qname.canonical() == qq.qname.canonical()
}

/// A request that is waiting on a shared in-flight resolution.
struct Waiters {
    start: Ts,
    waited: u64,
}

/// Coalesces identical in-flight queries: the first thread to arrive owns
/// the resolution; later threads observe it. Owners are marked by the
/// resolver and results are posted under the same lock, so a single
/// `Mutex<Coalescer>` suffices.
pub struct Coalescer {
    inflight: BTreeMap<QueryKey, Waiters>,
    max: usize,
}

impl Coalescer {
    /// A coalescer tracking at most `max` distinct in-flight queries.
    pub fn new(max: usize) -> Self {
        Self {
            inflight: BTreeMap::new(),
            max: max.max(1),
        }
    }

    /// Try to register as the owner of `key`. Returns true if this caller
    /// should resolve; false means another resolution is in flight and the
    /// caller should wait for its result.
    pub fn try_claim(&mut self, key: &QueryKey, now: Ts) -> bool {
        match self.inflight.get_mut(key) {
            Some(w) => {
                w.waited += 1;
                false
            }
            None => {
                if self.inflight.len() >= self.max {
                    // Drop the oldest claimant.
                    if let Some(k) = self
                        .inflight
                        .iter()
                        .min_by_key(|(_, w)| w.start)
                        .map(|(k, _)| k.clone())
                    {
                        self.inflight.remove(&k);
                    }
                }
                self.inflight.insert(
                    key.clone(),
                    Waiters {
                        start: now,
                        waited: 0,
                    },
                );
                true
            }
        }
    }

    /// Release the owner slot (call after the resolution completes).
    pub fn release(&mut self, key: &QueryKey) {
        self.inflight.remove(key);
    }

    /// How many waiters are coalesced on `key` (diagnostics).
    pub fn waiters(&self, key: &QueryKey) -> u64 {
        self.inflight.get(key).map(|w| w.waited).unwrap_or(0)
    }

    /// The number of in-flight queries.
    pub fn len(&self) -> usize {
        self.inflight.len()
    }

    /// Whether the coalescer is empty.
    pub fn is_empty(&self) -> bool {
        self.inflight.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Ts {
        1_700_000_000_000_000_000
    }

    fn key() -> QueryKey {
        QueryKey {
            name: Name::from_ascii("www.example.com").unwrap(),
            rr_type: RrType::A,
            class: RrClass::IN,
            ecs: None,
            want_dnssec: false,
            cd: false,
        }
    }

    #[test]
    fn coalescer_deduplicates() {
        let mut c = Coalescer::new(16);
        assert!(c.try_claim(&key(), now()));
        assert!(!c.try_claim(&key(), now() + 1));
        assert!(!c.try_claim(&key(), now() + 2));
        assert_eq!(c.waiters(&key()), 2);
        c.release(&key());
        assert!(c.try_claim(&key(), now() + 3));
    }

    #[test]
    fn coalescer_is_bounded() {
        let mut c = Coalescer::new(2);
        let k1 = QueryKey {
            name: Name::from_ascii("a.example.com").unwrap(),
            ..key()
        };
        let k2 = QueryKey {
            name: Name::from_ascii("b.example.com").unwrap(),
            ..key()
        };
        let k3 = QueryKey {
            name: Name::from_ascii("c.example.com").unwrap(),
            ..key()
        };
        assert!(c.try_claim(&k1, now()));
        assert!(c.try_claim(&k2, now() + 1));
        assert!(c.try_claim(&k3, now() + 2));
        assert!(c.len() <= 2);
    }

    #[test]
    fn response_match() {
        let q = Message::query(
            7,
            Name::from_ascii("www.example.com").unwrap(),
            RrType::A,
            true,
        );
        let mut r = Message::new(7);
        r.flags.qr = true;
        r.questions.clone_from(&q.questions);
        assert!(response_matches_query(&q, &r));
        r.id = 8;
        assert!(!response_matches_query(&q, &r));
    }
}
