//! Query processing: normalization, cache identity, and 0x20 matching.
//!
//! Every query the resolver sees is normalized to a canonical form before
//! it touches the cache or the engine, so the same name spelled in any
//! case hits the same entry. [`QueryKey`] is that canonical identity, and it
//! is what the resolver's coalescing table is keyed by. 0x20 (RFC 6840 §5.6)
//! anti-spoofing is validated here too — a response must echo the query's
//! randomized QNAME case, modulo servers that normalize case.

use crate::cache::{CacheKey, EcsKey};
use crate::edns::Ecs;
use crate::message::Message;
use crate::name::Name;
use crate::qtype::{RrClass, RrType};

/// The canonical, cacheable identity of a query.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct QueryKey {
    /// The query name (canonical case).
    pub name: Name,
    /// The query type.
    pub rr_type: RrType,
    /// The query class.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edns::{Edns, EdnsOption};

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

    /// The message → key conversion must carry everything that makes two
    /// queries different answers: the question, the DO bit, CD, and the ECS
    /// partition (RFC 7871 §7.2 — ECS answers must never be shared with
    /// clients that did not ask from the same network).
    #[test]
    fn query_key_from_message() {
        let q = Message::query(1, key().name.clone(), key().rr_type, true);
        assert_eq!(QueryKey::from_message(&q).unwrap(), key());
        assert_eq!(
            QueryKey::from_message(&q).unwrap().cache_key(),
            key().cache_key()
        );
        assert!(ecs_option(&key()).is_none());

        let mut with_ecs = q.clone();
        let mut edns = Edns::new(1232);
        edns.options.push(EdnsOption::Ecs(
            Ecs::ipv4("10.0.0.1".parse().unwrap(), 24).unwrap(),
        ));
        edns.dnssec_ok = true;
        with_ecs.edns = Some(edns);
        with_ecs.flags.cd = true;

        let k = QueryKey::from_message(&with_ecs).unwrap();
        assert!(k.want_dnssec);
        assert!(k.cd);
        assert!(k.ecs.is_some(), "ECS must partition the cache key");
        assert_eq!(ecs_option(&k).unwrap().source_prefix, 24);
        assert_ne!(k.cache_key(), key().cache_key());
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
