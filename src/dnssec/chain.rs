//! Root-to-answer authentication with a per-validation work envelope.

use super::{denial, dnskey_matches_ds, verify_rrsig, ValidationState, Verdict, Verification};
use crate::qtype::{DnssecAlgorithm, DsDigestType, Rcode, RrClass};
use crate::resolver::{Resolution, Resolver};
use crate::{Name, RData, Record, RrType};
use alloc::collections::BTreeMap;
use std::time::{Duration, Instant};

/// IANA root KSK-2017 and KSK-2024 DS anchors (RFC 9718). Operators can replace
/// this set for a private hierarchy or a future rollover. These are trust
/// configuration, never learned from an unauthenticated network response.
pub fn default_trust_anchors() -> Vec<Record> {
    [
        (
            20326,
            "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d",
        ),
        (
            38696,
            "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16",
        ),
    ]
    .into_iter()
    .map(|(key_tag, hex)| Record {
        name: Name::root(),
        rr_type: RrType::DS,
        class: RrClass::IN,
        ttl: u32::MAX,
        rdata: RData::Ds {
            key_tag,
            algorithm: DnssecAlgorithm::RSASHA256,
            digest_type: DsDigestType::SHA256,
            digest: hex
                .as_bytes()
                .chunks_exact(2)
                .map(|b| {
                    let digit = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
                    match b {
                        [a, b] => digit(*a) * 16 + digit(*b),
                        _ => 0,
                    }
                })
                .collect(),
        },
    })
    .collect()
}

/// A bounded, fresh-only store of complete evidence. The cache is deliberately
/// private and not persisted: ordinary answer-cache trust booleans are not
/// authentication evidence. Every reuse rechecks signatures and the chain.
#[derive(Default)]
pub(crate) struct EvidenceCache(BTreeMap<crate::cache::CacheKey, (Resolution, crate::time::Ts)>);

impl EvidenceCache {
    pub(crate) fn get(
        &mut self,
        key: &crate::cache::CacheKey,
        now: crate::time::Ts,
    ) -> Option<Resolution> {
        let (stored, when) = self.0.get(key)?;
        let age = now.saturating_sub(*when).max(0) / 1_000_000_000;
        let now_secs = (now / 1_000_000_000) as u32;
        let expired = stored.rrsigs.iter().chain(stored.authorities.iter()).any(|r| matches!(&r.rdata,
            RData::Rrsig { inception, expiration, .. } if !super::signature_time_valid(*inception, *expiration, now_secs)));
        if age >= i128::from(stored.ttl) || expired {
            self.0.remove(key);
            return None;
        }
        let mut res = stored.clone();
        res.ttl -= age as u32;
        for record in res
            .answers
            .iter_mut()
            .chain(res.rrsigs.iter_mut())
            .chain(res.authorities.iter_mut())
        {
            record.ttl = record.ttl.saturating_sub(age as u32);
        }
        res.from_cache = true;
        res.served_at = now;
        Some(res)
    }

    pub(crate) fn insert(
        &mut self,
        key: crate::cache::CacheKey,
        res: &Resolution,
        now: crate::time::Ts,
    ) {
        if res.ttl == 0 {
            return;
        }
        self.0.retain(|_, (r, at)| {
            now.saturating_sub(*at).max(0) / 1_000_000_000 < i128::from(r.ttl)
        });
        if self.0.len() >= 256 {
            if let Some(oldest) = self
                .0
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(k, _)| k.clone())
            {
                self.0.remove(&oldest);
            }
        }
        self.0.insert(key, (res.clone(), now));
    }
}

#[derive(Clone)]
struct Zone {
    name: Name,
    keys: Vec<Record>,
    insecure: bool,
}

type Groups = BTreeMap<(Name, RrType, RrClass), Vec<Record>>;

fn groups(records: &[Record]) -> Groups {
    let mut out = Groups::new();
    for r in records.iter().filter(|r| r.rr_type != RrType::RRSIG) {
        out.entry((r.name.clone(), r.rr_type, r.class))
            .or_default()
            .push(r.clone());
    }
    out
}

struct Context<'a> {
    resolver: &'a Resolver,
    now: u32,
    started: crate::time::Ts,
    validity: Vec<(u32, u32)>,
    deadline: Instant,
    fetches: usize,
    checks: usize,
    ttl: u32,
    zones: BTreeMap<Name, Zone>,
    material: BTreeMap<(Name, RrType), Resolution>,
}

impl Context<'_> {
    fn remaining_ttl(&self) -> u32 {
        let elapsed = (self.resolver.now().saturating_sub(self.started).max(0) / 1_000_000_000)
            .min(i128::from(u32::MAX)) as u32;
        self.ttl.saturating_sub(elapsed)
    }

    fn cache_material(&self, res: &Resolution) {
        self.resolver
            .cache_dnssec_material(res, self.remaining_ttl());
    }

    fn time(&self) -> Result<(), Verdict> {
        if Instant::now() >= self.deadline {
            Err(Verdict::Indeterminate)
        } else {
            Ok(())
        }
    }

    fn fetch(&mut self, name: &Name, qtype: RrType) -> Result<Resolution, Verdict> {
        self.time()?;
        let key = (name.clone(), qtype);
        if let Some(res) = self.material.get(&key) {
            return Ok(res.clone());
        }
        self.fetches += 1;
        if self.fetches > 128 {
            return Err(Verdict::Indeterminate);
        }
        let res = self
            .resolver
            .resolve_dnssec_material(name, qtype)
            .map_err(|_| Verdict::Indeterminate)?;
        self.time()?;
        self.material.insert(key, res.clone());
        Ok(res)
    }

    // Keys passed here have already been authenticated, except for the initial
    // DNSKEY RRset, for which they are restricted to DS/anchor-matching keys.
    fn signature(
        &mut self,
        records: &[Record],
        sigs: &[Record],
        zone: &Zone,
        wildcard: bool,
    ) -> Result<u8, Verdict> {
        let refs: Vec<_> = records.iter().collect();
        let first = records.first().ok_or(Verdict::Bogus)?;
        let mut candidates = 0;
        for sig in sigs {
            let RData::Rrsig {
                signer,
                type_covered,
                labels,
                inception,
                expiration,
                original_ttl,
                ..
            } = &sig.rdata
            else {
                continue;
            };
            if sig.name != first.name
                || sig.class != first.class
                || *type_covered != first.rr_type
                || *signer != zone.name
            {
                continue;
            }
            let literal_wildcard = sig.name.first_label() == Some(b"*")
                && usize::from(*labels) + 1 == sig.name.label_count();
            if !wildcard && usize::from(*labels) != sig.name.label_count() && !literal_wildcard {
                continue;
            }
            candidates += 1;
            if candidates > 8 {
                return Err(Verdict::Bogus);
            }
            for key in &zone.keys {
                self.time()?;
                // Charge only eligible key/signature pairs, and bound collisions.
                let RData::Dnskey {
                    flags,
                    protocol,
                    algorithm,
                    public_key,
                } = &key.rdata
                else {
                    continue;
                };
                let RData::Rrsig {
                    algorithm: sig_alg,
                    key_tag,
                    ..
                } = &sig.rdata
                else {
                    continue;
                };
                if algorithm != sig_alg
                    || super::key_tag(*flags, *protocol, algorithm.to_u8(), public_key) != *key_tag
                {
                    continue;
                }
                self.checks += 1;
                if self.checks > 128 {
                    return Err(Verdict::Bogus);
                }
                if verify_rrsig(key, sig, &refs, self.now) == Ok(true) {
                    self.validity.push((*inception, *expiration));
                    self.ttl = self
                        .ttl
                        .min(sig.ttl)
                        .min(*original_ttl)
                        .min(expiration.wrapping_sub(self.now));
                    for r in records {
                        self.ttl = self.ttl.min(r.ttl);
                    }
                    return Ok(*labels);
                }
            }
        }
        Err(Verdict::Bogus)
    }

    fn keys(&mut self, name: &Name, anchors: &[Record]) -> Result<Zone, Verdict> {
        let res = self.fetch(name, RrType::DNSKEY)?;
        if res.rcode != Rcode::NOERROR {
            return Err(Verdict::Bogus);
        }
        let keys: Vec<_> = res
            .answers
            .iter()
            .filter(|r| r.name == *name && r.class == RrClass::IN && r.rr_type == RrType::DNSKEY)
            .cloned()
            .collect();
        if keys.is_empty() || keys.len() > 64 {
            return Err(Verdict::Bogus);
        }
        let trusted: Vec<_> = keys
            .iter()
            .filter(|key| {
                anchors.iter().any(|anchor| {
                    dnskey_matches_ds(key, anchor)
                        || (anchor.rr_type == RrType::DNSKEY
                            && anchor.name == key.name
                            && anchor.class == key.class
                            && anchor.rdata == key.rdata)
                })
            })
            .cloned()
            .collect();
        if trusted.is_empty() {
            return Err(Verdict::Bogus);
        }
        self.signature(
            &keys,
            &res.rrsigs,
            &Zone {
                name: name.clone(),
                keys: trusted,
                insecure: false,
            },
            false,
        )?;
        self.ttl = self.ttl.min(res.ttl);
        self.cache_material(&res);
        Ok(Zone {
            name: name.clone(),
            keys,
            insecure: false,
        })
    }

    fn proof_records(
        &mut self,
        res: &Resolution,
        zone: &Zone,
        require_soa: bool,
    ) -> Result<Vec<Record>, Verdict> {
        let records: Vec<_> = res
            .authorities
            .iter()
            .filter(|r| matches!(r.rr_type, RrType::NSEC | RrType::NSEC3 | RrType::SOA))
            // Alias chains may carry proofs from several zones. A proof is
            // usable here only with this zone's covering signature; authority
            // RRsets from other zones are checked separately by validate().
            .filter(|r| {
                r.name.is_subdomain_of(&zone.name)
                    && res.authorities.iter().any(|sig| {
                        sig.name == r.name
                            && sig.class == r.class
                            && matches!(&sig.rdata,
                            RData::Rrsig { signer, type_covered, .. }
                                if signer == &zone.name && *type_covered == r.rr_type)
                    })
            })
            .cloned()
            .collect();
        if records.len() > 64 {
            return Err(Verdict::Bogus);
        }
        if require_soa
            && !records
                .iter()
                .any(|r| r.rr_type == RrType::SOA && r.name == zone.name)
        {
            return Err(Verdict::Bogus);
        }
        let mut authenticated = Vec::new();
        for ((_, rr_type, class), set) in groups(&records) {
            if class != RrClass::IN {
                return Err(Verdict::Bogus);
            }
            if rr_type == RrType::NSEC {
                // RFC 4034 section 4: each zone's NSEC RRset is a singleton.
                // A combined alias response can contain both the parent's
                // delegation NSEC and the child's apex NSEC at the same name.
                for record in set {
                    match self.signature(
                        core::slice::from_ref(&record),
                        &res.authorities,
                        zone,
                        false,
                    ) {
                        Ok(_) => authenticated.push(record),
                        Err(Verdict::Indeterminate) => return Err(Verdict::Indeterminate),
                        Err(_) => {}
                    }
                }
            } else {
                self.signature(&set, &res.authorities, zone, false)?;
                authenticated.extend(set);
            }
        }
        Ok(authenticated)
    }

    /// Walk label by label from the closest configured anchor. This also
    /// detects stripped signatures: silence about a DS is never an unsigned
    /// delegation without an authenticated NSEC/NSEC3 proof from the parent.
    fn zone(&mut self, owner: &Name) -> Result<Zone, Verdict> {
        if let Some(zone) = self.zones.get(owner) {
            return Ok(zone.clone());
        }
        let anchors = &self.resolver.config().engine.dnssec_trust_anchors;
        let anchor_name = anchors
            .iter()
            .filter(|r| owner.is_subdomain_of(&r.name))
            .max_by_key(|r| r.name.label_count())
            .map(|r| r.name.clone())
            .ok_or(Verdict::Indeterminate)?;
        let configured: Vec<_> = anchors
            .iter()
            .filter(|r| r.name == anchor_name)
            .cloned()
            .collect();
        let mut zone = if let Some(zone) = self.zones.get(&anchor_name) {
            zone.clone()
        } else {
            let zone = self.keys(&anchor_name, &configured)?;
            self.zones.insert(anchor_name.clone(), zone.clone());
            zone
        };
        let mut path = Vec::new();
        let mut suffix = owner.clone();
        while suffix != anchor_name {
            path.push(suffix.clone());
            suffix = suffix.parent().ok_or(Verdict::Bogus)?;
        }
        for name in path.into_iter().rev() {
            if let Some(known) = self.zones.get(&name) {
                zone = known.clone();
                continue;
            }
            if !zone.insecure {
                let res = self.fetch(&name, RrType::DS)?;
                let ds: Vec<_> = res
                    .answers
                    .iter()
                    .filter(|r| r.name == name && r.rr_type == RrType::DS && r.class == RrClass::IN)
                    .cloned()
                    .collect();
                if !ds.is_empty() {
                    if res.rcode != Rcode::NOERROR {
                        return Err(Verdict::Bogus);
                    }
                    self.signature(&ds, &res.rrsigs, &zone, false)?;
                    let supported: Vec<_> = ds.into_iter().filter(|r| matches!(&r.rdata,
                        RData::Ds { algorithm, digest_type, .. } if algorithm.supported() && matches!(*digest_type, DsDigestType::SHA256 | DsDigestType::SHA384))).collect();
                    zone = if supported.is_empty() {
                        Zone {
                            name: name.clone(),
                            keys: Vec::new(),
                            insecure: true,
                        }
                    } else {
                        self.keys(&name, &supported)?
                    };
                } else {
                    if !res.answers.is_empty() {
                        return Err(Verdict::Bogus);
                    }
                    let proofs = self.proof_records(&res, &zone, false)?;
                    let proof =
                        denial::negative(&name, RrType::DS, res.rcode, &zone.name, &proofs)?;
                    if proof.delegation || proof.opt_out {
                        zone = Zone {
                            name: name.clone(),
                            keys: Vec::new(),
                            insecure: true,
                        };
                    }
                }
                self.ttl = self.ttl.min(res.ttl);
                self.cache_material(&res);
            }
            self.zones.insert(name, zone.clone());
        }
        Ok(zone)
    }

    fn group(
        &mut self,
        records: &[Record],
        sigs: &[Record],
        authorities: &[Record],
    ) -> Result<bool, Verdict> {
        let first = records.first().ok_or(Verdict::Bogus)?;
        if first.class != RrClass::IN {
            return Err(Verdict::Bogus);
        }
        let owner = if first.rr_type == RrType::DS {
            first.name.parent().unwrap_or_else(Name::root)
        } else {
            first.name.clone()
        };
        let signers: alloc::collections::BTreeSet<_> = sigs
            .iter()
            .filter_map(|sig| match &sig.rdata {
                RData::Rrsig {
                    signer,
                    type_covered,
                    ..
                } if sig.name == first.name
                    && sig.class == first.class
                    && *type_covered == first.rr_type
                    && first.name.is_subdomain_of(signer) =>
                {
                    Some(signer.clone())
                }
                _ => None,
            })
            .collect();
        if signers.len() > 8 {
            return Err(Verdict::Bogus);
        }
        if signers.is_empty() {
            return if self.zone(&owner)?.insecure {
                Ok(false)
            } else {
                Err(Verdict::Bogus)
            };
        }
        let closest_anchor = self
            .resolver
            .config()
            .engine
            .dnssec_trust_anchors
            .iter()
            .filter(|r| first.name.is_subdomain_of(&r.name))
            .max_by_key(|r| r.name.label_count())
            .map(|r| &r.name)
            .ok_or(Verdict::Indeterminate)?;
        for signer in signers {
            if !signer.is_subdomain_of(closest_anchor) {
                continue;
            }
            let zone = match self.zone(&signer) {
                Ok(zone) => zone,
                Err(_) => continue,
            };
            if zone.insecure {
                return Ok(false);
            }
            if zone.name != signer || (first.rr_type == RrType::DS && signer == first.name) {
                continue;
            }
            let labels = match self.signature(
                records,
                sigs,
                &zone,
                !matches!(
                    first.rr_type,
                    RrType::DNSKEY | RrType::DS | RrType::NSEC | RrType::NSEC3 | RrType::SOA
                ),
            ) {
                Ok(labels) => labels,
                Err(_) => continue,
            };
            if usize::from(labels) < first.name.label_count()
                && first.name.first_label() != Some(b"*")
            {
                let proof_res = Resolution {
                    authorities: authorities.to_vec(),
                    ..empty_resolution(&first.name, first.rr_type)
                };
                let proofs = self.proof_records(&proof_res, &zone, false)?;
                if denial::expanded(&first.name, labels, &zone.name, &proofs)? {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        Err(Verdict::Bogus)
    }
}

pub(super) fn empty_resolution(name: &Name, rr_type: RrType) -> Resolution {
    Resolution {
        name: name.clone(),
        rr_type,
        class: RrClass::IN,
        rcode: Rcode::NOERROR,
        answers: Vec::new(),
        authorities: Vec::new(),
        rrsigs: Vec::new(),
        validated: false,
        ttl: 0,
        from_cache: false,
        stale: false,
        ecs_scope: None,
        served_at: 0,
    }
}

pub(super) fn validate(resolver: &Resolver, res: &Resolution) -> (Verification, u32) {
    let _scope = crate::background::TaskScope::enter_query(
        resolver.config().engine.fetch_limits,
        resolver.config().engine.query_budget_ms,
    );
    let started = resolver.now();
    let mut ctx = Context {
        resolver,
        now: (started / 1_000_000_000) as u32,
        started,
        validity: Vec::new(),
        deadline: crate::background::task_deadline().unwrap_or_else(|| {
            Instant::now() + Duration::from_millis(resolver.config().engine.query_budget_ms)
        }),
        fetches: 0,
        checks: 0,
        ttl: res.ttl,
        zones: BTreeMap::new(),
        material: BTreeMap::new(),
    };
    if matches!(res.rr_type, RrType::DNSKEY | RrType::DS) {
        ctx.material
            .insert((res.name.clone(), res.rr_type), res.clone());
    }
    let answer_groups = groups(&res.answers);
    let mut report = Verification {
        answer_groups: answer_groups.len(),
        ..Verification::empty()
    };
    let result = (|| {
        let mut insecure = false;
        for ((name, rr_type, _), records) in &answer_groups {
            // RFC 6672: the synthesized CNAME is authenticated by its DNAME.
            let synthesized = *rr_type == RrType::CNAME && records.len() == 1 && res.answers.iter().any(|r| {
                let RData::Dname(target) = &r.rdata else { return false; };
                records.first().is_some_and(|record| matches!(&record.rdata, RData::Cname(actual) if crate::engine::synthesize_dname_cname(name, &r.name, target).as_ref() == Some(actual)))
            });
            let secure = synthesized || ctx.group(records, &res.rrsigs, &res.authorities)?;
            if secure {
                report.answer_groups_authenticated += 1;
            } else {
                insecure = true;
            }
        }
        let mut authority_secure = true;
        for ((_, rr_type, _), records) in groups(&res.authorities) {
            if rr_type == RrType::NSEC {
                for record in records {
                    authority_secure &=
                        ctx.group(core::slice::from_ref(&record), &res.authorities, &[])?;
                }
            } else {
                authority_secure &= ctx.group(&records, &res.authorities, &[])?;
            }
        }
        if !res.authorities.is_empty() {
            report.authority_authenticated = Some(authority_secure);
        }
        insecure |= !authority_secure;
        let mut terminal = res.name.clone();
        if res.rr_type != RrType::CNAME {
            let mut seen = alloc::collections::BTreeSet::new();
            loop {
                if !seen.insert(terminal.clone()) {
                    return Err(Verdict::Bogus);
                }
                let Some(next) = res.answers.iter().find_map(|r| match &r.rdata {
                    RData::Cname(target) if r.name == terminal => Some(target.clone()),
                    _ => None,
                }) else {
                    break;
                };
                terminal = next;
            }
        }
        let positive = res.answers.iter().any(|r| {
            r.name == terminal && (r.rr_type == res.rr_type || res.rr_type == RrType::ANY)
        });
        if !positive || res.rcode == Rcode::NXDOMAIN {
            if positive {
                return Err(Verdict::Bogus);
            }
            let proof_zone = res
                .authorities
                .iter()
                .filter(|r| r.rr_type == RrType::SOA && terminal.is_subdomain_of(&r.name))
                .max_by_key(|r| r.name.label_count())
                .map(|r| &r.name)
                .unwrap_or(&terminal);
            let zone = ctx.zone(proof_zone)?;
            if zone.insecure {
                insecure = true;
            } else {
                let proofs = ctx.proof_records(res, &zone, true)?;
                let proof =
                    denial::negative(&terminal, res.rr_type, res.rcode, &zone.name, &proofs)?;
                insecure |= proof.opt_out;
                report.authority_authenticated = Some(true);
            }
        } else if res.rcode != Rcode::NOERROR {
            return Err(Verdict::Bogus);
        }
        ctx.time()?;
        // Fetching later links can consume the remaining lifetime of a key or
        // signature already checked. Recheck every accepted window at delivery.
        let delivered = (resolver.now() / 1_000_000_000) as u32;
        if ctx
            .validity
            .iter()
            .any(|(start, end)| !super::signature_time_valid(*start, *end, delivered))
        {
            return Err(Verdict::Bogus);
        }
        Ok(insecure)
    })();
    match result {
        Ok(false) => {
            report.verdict = Verdict::SignatureValid;
            report.state = ValidationState::ChainAnchored;
        }
        Ok(true) => {
            report.verdict = Verdict::Insecure;
            report.state = ValidationState::Insecure;
        }
        Err(verdict) => {
            report.verdict = verdict;
            report.state = ValidationState::Indeterminate;
        }
    }
    (report, ctx.remaining_ttl())
}
