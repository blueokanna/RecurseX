//! Signed, hermetic root -> test -> example.test hierarchy. The fixture signs
//! wire RRsets independently of the validator's canonicalization routine.
#![cfg(feature = "dnssec")]

use recurse_x::qtype::{DnssecAlgorithm, DsDigestType, Rcode, RrClass};
use recurse_x::{ErrorKind, Message, Name, RData, Record, Resolver, ResolverConfig, RrType};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::collections::BTreeMap;
use std::net::UdpSocket;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}
fn now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}
fn record(owner: &str, rr_type: RrType, rdata: RData) -> Record {
    Record {
        name: name(owner),
        rr_type,
        class: RrClass::IN,
        ttl: 300,
        rdata,
    }
}

struct Key {
    owner: Name,
    pair: Ed25519KeyPair,
    flags: u16,
}
impl Key {
    fn new(owner: &str, seed: u8, flags: u16) -> Self {
        Self {
            owner: name(owner),
            pair: Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap(),
            flags,
        }
    }
    fn dnskey(&self) -> Record {
        record(
            &self.owner.to_ascii(),
            RrType::DNSKEY,
            RData::Dnskey {
                flags: self.flags,
                protocol: 3,
                algorithm: DnssecAlgorithm::ED25519,
                public_key: self.pair.public_key().as_ref().to_vec(),
            },
        )
    }
    fn ds(&self) -> Record {
        let key = self.dnskey();
        let mut input = self.owner.as_bytes().to_vec();
        key.rdata.to_wire(&mut input, None);
        record(
            &self.owner.to_ascii(),
            RrType::DS,
            RData::Ds {
                key_tag: recurse_x::dnssec::key_tag(
                    self.flags,
                    3,
                    15,
                    self.pair.public_key().as_ref(),
                ),
                algorithm: DnssecAlgorithm::ED25519,
                digest_type: DsDigestType::SHA256,
                digest: ring::digest::digest(&ring::digest::SHA256, &input)
                    .as_ref()
                    .to_vec(),
            },
        )
    }
    fn sign(&self, records: &[Record]) -> Record {
        self.sign_window(records, now() - 60, now() + 3600)
    }
    fn sign_window(&self, records: &[Record], inception: u32, expiration: u32) -> Record {
        let first = &records[0];
        let labels =
            first.name.label_count() as u8 - u8::from(first.name.first_label() == Some(b"*"));
        let key_tag =
            recurse_x::dnssec::key_tag(self.flags, 3, 15, self.pair.public_key().as_ref());
        let mut data = Vec::new();
        data.extend_from_slice(&first.rr_type.to_u16().to_be_bytes());
        data.extend_from_slice(&[15, labels]);
        data.extend_from_slice(&300u32.to_be_bytes());
        data.extend_from_slice(&expiration.to_be_bytes());
        data.extend_from_slice(&inception.to_be_bytes());
        data.extend_from_slice(&key_tag.to_be_bytes());
        self.owner.write_wire(&mut data);
        let mut rdata: Vec<Vec<u8>> = records
            .iter()
            .map(|r| {
                let mut b = Vec::new();
                r.rdata.to_wire(&mut b, None);
                b
            })
            .collect();
        rdata.sort();
        rdata.dedup();
        for bytes in rdata {
            first.name.write_wire(&mut data);
            data.extend_from_slice(&first.rr_type.to_u16().to_be_bytes());
            data.extend_from_slice(&1u16.to_be_bytes());
            data.extend_from_slice(&300u32.to_be_bytes());
            data.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            data.extend_from_slice(&bytes);
        }
        record(
            &first.name.to_ascii(),
            RrType::RRSIG,
            RData::Rrsig {
                type_covered: first.rr_type,
                algorithm: DnssecAlgorithm::ED25519,
                labels,
                original_ttl: 300,
                expiration,
                inception,
                key_tag,
                signer: self.owner.clone(),
                signature: self.pair.sign(&data).as_ref().to_vec(),
            },
        )
    }
    fn signed(&self, records: Vec<Record>) -> Vec<Record> {
        let sig = self.sign(&records);
        let mut result = records;
        result.push(sig);
        result
    }
}

fn soa(zone: &str) -> Record {
    record(
        zone,
        RrType::SOA,
        RData::Soa {
            mname: name(zone),
            rname: name(zone),
            serial: 1,
            refresh: 300,
            retry: 300,
            expire: 3600,
            minimum: 60,
        },
    )
}
fn a(owner: &str) -> Record {
    record(owner, RrType::A, RData::A("192.0.2.42".parse().unwrap()))
}
fn nsec(owner: &str, next: &str, types: Vec<RrType>) -> Record {
    record(
        owner,
        RrType::NSEC,
        RData::Nsec {
            next: name(next),
            types,
        },
    )
}
fn base32(bytes: &[u8]) -> String {
    let alphabet = b"0123456789abcdefghijklmnopqrstuv";
    let mut bits = 0u32;
    let mut count = 0;
    let mut result = String::new();
    for b in bytes {
        bits = (bits << 8) | u32::from(*b);
        count += 8;
        while count >= 5 {
            count -= 5;
            result.push(alphabet[((bits >> count) & 31) as usize] as char);
        }
    }
    result
}
fn nsec3(owner: &str, zone: &str, types: Vec<RrType>, flags: u8) -> Record {
    let hash = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        name(owner).as_bytes(),
    );
    record(
        &format!("{}.{}", base32(hash.as_ref()), zone),
        RrType::NSEC3,
        RData::Nsec3 {
            hash_alg: 1,
            flags,
            iterations: 0,
            salt: Vec::new(),
            next_hashed: hash.as_ref().to_vec(),
            types,
        },
    )
}

struct Fixture {
    root: Key,
    tld: Key,
    ksk: Key,
    zsk: Key,
    replies: BTreeMap<(Name, RrType), Message>,
}
impl Fixture {
    fn new() -> Self {
        let root = Key::new(".", 1, 257);
        let tld = Key::new("test", 2, 257);
        let ksk = Key::new("example.test", 3, 257);
        let zsk = Key::new("example.test", 4, 256);
        let mut replies = BTreeMap::new();
        for key in [&root, &tld] {
            let mut msg = Message::new(0);
            msg.answers = key.signed(vec![key.dnskey()]);
            replies.insert((key.owner.clone(), RrType::DNSKEY), msg);
        }
        let mut msg = Message::new(0);
        msg.answers = ksk.signed(vec![ksk.dnskey(), zsk.dnskey()]);
        replies.insert((ksk.owner.clone(), RrType::DNSKEY), msg);
        for (parent, child) in [(&root, &tld), (&tld, &ksk)] {
            let mut msg = Message::new(0);
            msg.answers = parent.signed(vec![child.ds()]);
            replies.insert((child.owner.clone(), RrType::DS), msg);
        }
        let mut msg = Message::new(0);
        msg.answers = zsk.signed(vec![a("www.example.test")]);
        replies.insert((name("www.example.test"), RrType::A), msg);
        Self {
            root,
            tld,
            ksk,
            zsk,
            replies,
        }
    }
    fn denial(&mut self, owner: &str, qtype: RrType, code: Rcode, proofs: Vec<Record>) {
        let mut msg = Message::new(0);
        msg.flags.rcode = code;
        msg.authorities = self.zsk.signed(vec![soa("example.test")]);
        for proof in proofs {
            msg.authorities.extend(self.zsk.signed(vec![proof]));
        }
        self.replies.insert((name(owner), qtype), msg);
    }
    fn run(self) -> (Resolver, Stub) {
        let anchor = self.root.ds();
        let stub = Stub::start(self);
        let mut cfg = ResolverConfig::default();
        cfg.engine.dnssec = true;
        cfg.engine.dnssec_trust_anchors = vec![anchor];
        cfg.engine.root_servers = vec![stub.addr];
        cfg.engine.auth_port = stub.addr.port();
        cfg.engine.timeout_ms = 100;
        cfg.engine.query_budget_ms = 1500;
        (Resolver::new(cfg), stub)
    }
}

struct Stub {
    addr: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    seen: Arc<Mutex<Vec<(Name, RrType)>>>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Stub {
    fn start(fixture: Fixture) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let addr = socket.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let worker = std::thread::spawn(move || {
            let mut buf = [0; 8192];
            while !flag.load(Ordering::Relaxed) {
                let Ok((len, peer)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                let query = Message::parse(&buf[..len]).unwrap();
                let question = query.question().unwrap();
                let key = (question.qname.clone(), question.qtype);
                log.lock().unwrap().push(key.clone());
                let mut response = if let Some(msg) = fixture.replies.get(&key) {
                    msg.clone()
                } else if question.qtype == RrType::DS
                    && question.qname.is_strict_subdomain_of(&fixture.ksk.owner)
                {
                    let mut msg = Message::new(0);
                    msg.authorities = fixture.zsk.signed(vec![soa("example.test")]);
                    msg.authorities.extend(fixture.zsk.signed(vec![nsec(
                        &question.qname.to_ascii(),
                        "z.example.test",
                        vec![RrType::A, RrType::NSEC, RrType::RRSIG],
                    )]));
                    msg
                } else if !matches!(question.qtype, RrType::DS | RrType::DNSKEY)
                    && matches!(question.qname.to_ascii().as_str(), "test" | "example.test")
                {
                    let mut msg = Message::new(0);
                    let zone = question.qname.to_ascii();
                    msg.authorities.push(record(
                        &zone,
                        RrType::NS,
                        RData::Ns(name(&format!("ns.{zone}"))),
                    ));
                    msg.additionals.push(record(
                        &format!("ns.{zone}"),
                        RrType::A,
                        RData::A("127.0.0.1".parse().unwrap()),
                    ));
                    msg
                } else {
                    let mut msg = Message::new(0);
                    msg.flags.rcode = Rcode::SERVFAIL;
                    msg
                };
                response.id = query.id;
                response.flags.qr = true;
                response.flags.aa = true;
                response.questions = query.questions;
                socket.send_to(&response.to_bytes().unwrap(), peer).unwrap();
            }
        });
        Self {
            addr,
            stop,
            seen,
            worker: Some(worker),
        }
    }
}
impl Drop for Stub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let result = self.worker.take().unwrap().join();
        if !std::thread::panicking() {
            result.unwrap();
        }
    }
}

#[test]
fn root_ds_dnskey_zsk_answer_chain_and_cache_are_authenticated() {
    let (resolver, stub) = Fixture::new().run();
    let answer = resolver
        .resolve(&name("www.example.test"), RrType::A)
        .unwrap();
    assert!(answer.validated);
    assert!(!answer.from_cache);
    let count = stub.seen.lock().unwrap().len();
    for key in [
        (name("."), RrType::DNSKEY),
        (name("test"), RrType::DS),
        (name("test"), RrType::DNSKEY),
        (name("example.test"), RrType::DS),
        (name("example.test"), RrType::DNSKEY),
    ] {
        assert!(stub.seen.lock().unwrap().contains(&key), "missing {key:?}");
    }
    let cached = resolver
        .resolve(&name("www.example.test"), RrType::A)
        .unwrap();
    assert!(cached.validated && cached.from_cache);
    assert_eq!(
        count,
        stub.seen.lock().unwrap().len(),
        "fresh proof reuse must not query upstream"
    );
    let mut query = Message::query(1, name("www.example.test"), RrType::A, true);
    query.flags.ad = true;
    assert!(resolver.build_response(&query, &cached).flags.ad);
    query.flags.cd = true;
    assert!(!resolver.build_response(&query, &cached).flags.ad);
}

#[test]
fn broken_links_missing_signatures_and_forged_keys_fail_closed() {
    for fault in 0..6 {
        let mut fixture = Fixture::new();
        let key = match fault {
            0 => (name("test"), RrType::DS),
            1 | 2 => (name("example.test"), RrType::DNSKEY),
            _ => (name("www.example.test"), RrType::A),
        };
        let msg = fixture.replies.get_mut(&key).unwrap();
        match fault {
            0 => {
                if let RData::Ds { digest, .. } = &mut msg.answers[0].rdata {
                    digest[0] ^= 1;
                }
            }
            1 => {
                if let RData::Dnskey { public_key, .. } = &mut msg.answers[1].rdata {
                    public_key[0] ^= 1;
                }
            }
            2 | 3 => msg.answers.retain(|r| r.rr_type != RrType::RRSIG),
            4 => {
                if let RData::Rrsig { signature, .. } = &mut msg.answers[1].rdata {
                    signature[0] ^= 1;
                }
            }
            _ => {
                msg.answers[1] = fixture
                    .zsk
                    .sign_window(&msg.answers[..1], now() - 100, now() - 1);
            }
        }
        let (resolver, _stub) = fixture.run();
        for _ in 0..2 {
            assert_eq!(
                resolver
                    .resolve(&name("www.example.test"), RrType::A)
                    .unwrap_err()
                    .kind,
                ErrorKind::Dnssec,
                "fault {fault}"
            );
        }
    }
}

#[test]
fn nsec_and_nsec3_negative_answers_preserve_proofs_across_cache_hits() {
    for hashed in [false, true] {
        for nx in [false, true] {
            let mut fixture = Fixture::new();
            let owner = "absent.example.test";
            let proof = if hashed {
                nsec3(
                    if nx { "example.test" } else { owner },
                    "example.test",
                    if nx {
                        vec![RrType::SOA, RrType::NS, RrType::DNSKEY]
                    } else {
                        vec![RrType::TXT]
                    },
                    0,
                )
            } else if nx {
                nsec(
                    "example.test",
                    "z.example.test",
                    vec![
                        RrType::SOA,
                        RrType::NS,
                        RrType::DNSKEY,
                        RrType::NSEC,
                        RrType::RRSIG,
                    ],
                )
            } else {
                nsec(
                    owner,
                    "z.example.test",
                    vec![RrType::TXT, RrType::NSEC, RrType::RRSIG],
                )
            };
            fixture.denial(
                owner,
                RrType::A,
                if nx { Rcode::NXDOMAIN } else { Rcode::NOERROR },
                vec![proof],
            );
            let (resolver, stub) = fixture.run();
            let answer = resolver.resolve(&name(owner), RrType::A).unwrap();
            assert!(answer.validated);
            assert!(answer
                .authorities
                .iter()
                .any(|r| matches!(r.rr_type, RrType::NSEC | RrType::NSEC3)));
            let count = stub.seen.lock().unwrap().len();
            let cached = resolver.resolve(&name(owner), RrType::A).unwrap();
            assert!(cached.validated && cached.from_cache);
            assert_eq!(count, stub.seen.lock().unwrap().len());
        }
    }
}

#[test]
fn authenticated_nsec_and_nsec3_optout_establish_unsigned_delegations() {
    for optout in [false, true] {
        let mut fixture = Fixture::new();
        let mut msg = Message::new(0);
        msg.authorities = fixture.tld.signed(vec![soa("test")]);
        let proof = if optout {
            nsec3("test", "test", vec![RrType::SOA, RrType::NS], 1)
        } else {
            nsec(
                "unsigned.test",
                "z.test",
                vec![RrType::NS, RrType::NSEC, RrType::RRSIG],
            )
        };
        msg.authorities.extend(fixture.tld.signed(vec![proof]));
        fixture
            .replies
            .insert((name("unsigned.test"), RrType::DS), msg);
        let mut msg = Message::new(0);
        msg.answers.push(a("host.unsigned.test"));
        // An insecure delegation makes child signatures irrelevant, including
        // expired or deliberately bogus signatures supplied by that child.
        let untrusted = Key::new("unsigned.test", 99, 256);
        msg.answers
            .push(untrusted.sign_window(&msg.answers, now() - 100, now() - 1));
        fixture
            .replies
            .insert((name("host.unsigned.test"), RrType::A), msg);
        let (resolver, _stub) = fixture.run();
        let mut cfg = resolver.config().clone();
        cfg.engine.qname_minimization = false;
        let resolver = Resolver::new(cfg);
        let answer = resolver
            .resolve(&name("host.unsigned.test"), RrType::A)
            .unwrap();
        assert!(!answer.validated);
    }
}

#[test]
fn wildcard_expansion_needs_authenticated_nonexistence_of_next_closer() {
    for hashed in [false, true] {
        for with_proof in [false, true] {
            let mut fixture = Fixture::new();
            let mut records = fixture.zsk.signed(vec![a("*.example.test")]);
            for r in &mut records {
                r.name = name("wild.example.test");
            }
            let mut msg = Message::new(0);
            msg.answers = records;
            if with_proof {
                let proof = if hashed {
                    nsec3(
                        "example.test",
                        "example.test",
                        vec![RrType::SOA, RrType::NS],
                        0,
                    )
                } else {
                    nsec(
                        "example.test",
                        "z.example.test",
                        vec![RrType::SOA, RrType::NS, RrType::NSEC, RrType::RRSIG],
                    )
                };
                msg.authorities.extend(fixture.zsk.signed(vec![proof]));
            }
            fixture
                .replies
                .insert((name("wild.example.test"), RrType::A), msg);
            let (resolver, _stub) = fixture.run();
            let result = resolver.resolve(&name("wild.example.test"), RrType::A);
            if with_proof {
                assert!(result.unwrap().validated);
            } else {
                assert_eq!(result.unwrap_err().kind, ErrorKind::Dnssec);
            }
        }
    }
}

#[test]
fn wildcard_alias_to_negative_answer_keeps_each_zones_denial_proof() {
    let mut fixture = Fixture::new();
    let alias = record(
        "*.example.test",
        RrType::CNAME,
        RData::Cname(name("missing.test")),
    );
    let mut response = Message::new(0);
    response.answers = fixture.zsk.signed(vec![alias]);
    for record in &mut response.answers {
        record.name = name("alias.example.test");
    }
    response.authorities = fixture.zsk.signed(vec![nsec(
        "example.test",
        "z.example.test",
        vec![RrType::SOA, RrType::NS, RrType::NSEC, RrType::RRSIG],
    )]);
    fixture
        .replies
        .insert((name("alias.example.test"), RrType::A), response);
    let mut response = Message::new(0);
    response.flags.rcode = Rcode::NXDOMAIN;
    response.authorities = fixture.tld.signed(vec![soa("test")]);
    response.authorities.extend(fixture.tld.signed(vec![nsec(
        "test",
        "example.test",
        vec![RrType::SOA, RrType::NS, RrType::NSEC, RrType::RRSIG],
    )]));
    response.authorities.extend(fixture.tld.signed(vec![nsec(
        "example.test",
        "z.test",
        vec![RrType::NS, RrType::DS, RrType::NSEC, RrType::RRSIG],
    )]));
    fixture
        .replies
        .insert((name("missing.test"), RrType::A), response);
    let (resolver, _stub) = fixture.run();
    let mut cfg = resolver.config().clone();
    cfg.engine.qname_minimization = false;
    let resolver = Resolver::new(cfg);
    let result = resolver
        .resolve(&name("alias.example.test"), RrType::A)
        .unwrap();
    assert!(result.validated);
    assert_eq!(result.rcode, Rcode::NXDOMAIN);
    assert_eq!(result.answers[0].rr_type, RrType::CNAME);
    assert!(
        resolver
            .resolve(&name("alias.example.test"), RrType::A)
            .unwrap()
            .validated
    );
}

#[test]
fn wildcard_nodata_authenticates_the_literal_wildcard_nsec() {
    for hashed in [false, true] {
        for nx in [false, true] {
            let mut fixture = Fixture::new();
            let proofs = if hashed {
                let mut apex = nsec3(
                    "example.test",
                    "example.test",
                    vec![RrType::SOA, RrType::NS],
                    0,
                );
                let mut wildcard = nsec3("*.example.test", "example.test", vec![RrType::TXT], 0);
                if let (RData::Nsec3 { next_hashed: a, .. }, RData::Nsec3 { next_hashed: b, .. }) =
                    (&mut apex.rdata, &mut wildcard.rdata)
                {
                    std::mem::swap(a, b);
                }
                vec![apex, wildcard]
            } else {
                vec![nsec(
                    "*.example.test",
                    "z.example.test",
                    vec![RrType::TXT, RrType::NSEC, RrType::RRSIG],
                )]
            };
            fixture.denial(
                "wild.example.test",
                RrType::A,
                if nx { Rcode::NXDOMAIN } else { Rcode::NOERROR },
                proofs,
            );
            let (resolver, _stub) = fixture.run();
            let result = resolver.resolve(&name("wild.example.test"), RrType::A);
            if nx {
                assert_eq!(result.unwrap_err().kind, ErrorKind::Dnssec);
            } else {
                assert!(result.unwrap().validated);
            }
        }
    }
}

#[test]
fn signed_nsec_cannot_cross_zone_boundaries_or_wrap_before_the_apex() {
    for next in ["outside.test", "a.example.test", "www.example.test"] {
        let mut fixture = Fixture::new();
        fixture.denial(
            "www.example.test",
            RrType::AAAA,
            Rcode::NOERROR,
            vec![nsec(
                "www.example.test",
                next,
                vec![RrType::A, RrType::NSEC, RrType::RRSIG],
            )],
        );
        let (resolver, _stub) = fixture.run();
        assert_eq!(
            resolver
                .resolve(&name("www.example.test"), RrType::AAAA)
                .unwrap_err()
                .kind,
            ErrorKind::Dnssec,
            "next={next}"
        );
    }
}

#[test]
fn json_trust_anchors_replace_defaults_and_reject_malformed_digests() {
    use recurse_x::config::Config;
    let json = r#"{"engine":{"dnssec":true,"dnssecTrustAnchors":[{"name":".","keyTag":38696,"algorithm":8,"digestType":2,"digest":"683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16"}]}}"#;
    let cfg = Config::from_json_str(json)
        .unwrap()
        .into_resolver_config()
        .unwrap();
    assert!(cfg.engine.dnssec);
    assert_eq!(cfg.engine.dnssec_trust_anchors.len(), 1);
    assert_eq!(
        cfg.engine.dnssec_trust_anchors[0],
        recurse_x::dnssec::default_trust_anchors()[1]
    );
    for digest in [
        "00",
        "g83d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16",
    ] {
        let malformed = json.replace(
            "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16",
            digest,
        );
        assert!(Config::from_json_str(&malformed)
            .unwrap()
            .into_resolver_config()
            .is_err());
    }
    let cfg = Config::from_json_str(r#"{"engine":{"dnssec":true,"dnssecTrustAnchors":[]}}"#)
        .unwrap()
        .into_resolver_config()
        .unwrap();
    assert!(cfg.engine.dnssec_trust_anchors.is_empty());
}

#[test]
fn valid_signatures_do_not_turn_unrelated_negative_proofs_into_answers() {
    for hashed in [false, true] {
        let mut fixture = Fixture::new();
        let proof = if hashed {
            nsec3("other.example.test", "example.test", vec![RrType::TXT], 0)
        } else {
            nsec(
                "other.example.test",
                "z.example.test",
                vec![RrType::TXT, RrType::NSEC, RrType::RRSIG],
            )
        };
        fixture.denial("example.test", RrType::AAAA, Rcode::NOERROR, vec![proof]);
        let (resolver, _stub) = fixture.run();
        assert_eq!(
            resolver
                .resolve(&name("example.test"), RrType::AAAA)
                .unwrap_err()
                .kind,
            ErrorKind::Dnssec
        );
    }
}

#[test]
fn checking_disabled_can_return_bogus_data_but_never_sets_ad() {
    let mut fixture = Fixture::new();
    fixture
        .replies
        .get_mut(&(name("www.example.test"), RrType::A))
        .unwrap()
        .answers
        .retain(|r| r.rr_type != RrType::RRSIG);
    let (resolver, _stub) = fixture.run();
    let mut query = Message::query(1, name("www.example.test"), RrType::A, true);
    query.flags.cd = true;
    query.flags.ad = true;
    let response = resolver.handle_query(&query, None);
    assert_eq!(response.flags.rcode, Rcode::NOERROR);
    assert!(!response.flags.ad);
    query.flags.cd = false;
    assert_eq!(
        resolver.handle_query(&query, None).flags.rcode,
        Rcode::SERVFAIL
    );
}

#[test]
fn cname_and_synthesized_dname_chains_authenticate_every_link() {
    for dname in [false, true] {
        let mut fixture = Fixture::new();
        let mut msg = Message::new(0);
        let alias = if dname {
            record(
                "alias.example.test",
                RrType::DNAME,
                RData::Dname(name("example.test")),
            )
        } else {
            record(
                "www.alias.example.test",
                RrType::CNAME,
                RData::Cname(name("www.example.test")),
            )
        };
        msg.answers = fixture.zsk.signed(vec![alias]);
        fixture
            .replies
            .insert((name("www.alias.example.test"), RrType::A), msg);
        let (resolver, _stub) = fixture.run();
        let mut cfg = resolver.config().clone();
        cfg.engine.qname_minimization = false;
        let resolver = Resolver::new(cfg);
        let answer = resolver
            .resolve(&name("www.alias.example.test"), RrType::A)
            .unwrap();
        assert!(answer.validated);
        assert!(answer.answers.iter().any(|r| r.rr_type == RrType::A));
        assert!(
            resolver
                .resolve(&name("www.alias.example.test"), RrType::A)
                .unwrap()
                .validated
        );
    }
}

#[test]
fn wrong_or_missing_anchor_cannot_be_overridden_by_the_legacy_boolean() {
    for missing in [false, true] {
        let (resolver, _stub) = Fixture::new().run();
        let mut cfg = resolver.config().clone();
        cfg.engine.dnssec_anchored = true;
        if missing {
            cfg.engine.dnssec_trust_anchors.clear();
        } else if let RData::Ds { digest, .. } = &mut cfg.engine.dnssec_trust_anchors[0].rdata {
            digest[0] ^= 1;
        }
        assert_eq!(
            Resolver::new(cfg)
                .resolve(&name("www.example.test"), RrType::A)
                .unwrap_err()
                .kind,
            ErrorKind::Dnssec
        );
    }
}

#[test]
fn sha384_ds_and_rollover_sets_accept_a_valid_path() {
    let mut fixture = Fixture::new();
    let mut ds = fixture.ksk.ds();
    let mut bytes = fixture.ksk.owner.as_bytes().to_vec();
    fixture.ksk.dnskey().rdata.to_wire(&mut bytes, None);
    if let RData::Ds {
        digest_type,
        digest,
        ..
    } = &mut ds.rdata
    {
        *digest_type = DsDigestType::SHA384;
        *digest = ring::digest::digest(&ring::digest::SHA384, &bytes)
            .as_ref()
            .to_vec();
    }
    let mut retired = ds.clone();
    if let RData::Ds { key_tag, .. } = &mut retired.rdata {
        *key_tag ^= 1;
    }
    let msg = fixture
        .replies
        .get_mut(&(name("example.test"), RrType::DS))
        .unwrap();
    msg.answers = fixture.tld.signed(vec![retired, ds]);
    let (resolver, _stub) = fixture.run();
    assert!(
        resolver
            .resolve(&name("www.example.test"), RrType::A)
            .unwrap()
            .validated
    );
}

#[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
#[test]
fn forwarded_nsec3_proofs_use_the_same_validation_and_cache_path() {
    let mut fixture = Fixture::new();
    fixture.denial(
        "absent.example.test",
        RrType::A,
        Rcode::NXDOMAIN,
        vec![nsec3(
            "example.test",
            "example.test",
            vec![RrType::SOA, RrType::NS],
            0,
        )],
    );
    let (resolver, stub) = fixture.run();
    let mut cfg = resolver.config().clone();
    cfg.dns.upstreams.default = vec![recurse_x::forward::Forwarder::plain(
        recurse_x::upstream::Endpoint::new(
            stub.addr.ip(),
            stub.addr.port(),
            recurse_x::upstream::Proto::Udp,
        ),
    )];
    let resolver = Resolver::new(cfg);
    for _ in 0..2 {
        let res = resolver
            .resolve(&name("absent.example.test"), RrType::A)
            .unwrap();
        assert!(res.validated);
    }
}

#[test]
fn every_supported_signature_algorithm_verifies_and_rejects_tampering() {
    use ring::signature as sig;
    let rng = ring::rand::SystemRandom::new();
    for algorithm in [8, 10, 13, 14, 15] {
        let rsa =
            sig::RsaKeyPair::from_pkcs8(include_bytes!("fixtures/dnssec/rsa2048.pk8")).unwrap();
        let ec_alg = if algorithm == 14 {
            &sig::ECDSA_P384_SHA384_FIXED_SIGNING
        } else {
            &sig::ECDSA_P256_SHA256_FIXED_SIGNING
        };
        let ec_pkcs8 = sig::EcdsaKeyPair::generate_pkcs8(ec_alg, &rng).unwrap();
        let ec = sig::EcdsaKeyPair::from_pkcs8(ec_alg, ec_pkcs8.as_ref(), &rng).unwrap();
        let ed = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
        let public_key = match algorithm {
            8 | 10 => include_bytes!("fixtures/dnssec/rsa2048.dnskey").to_vec(),
            13 | 14 => ec.public_key().as_ref()[1..].to_vec(),
            _ => ed.public_key().as_ref().to_vec(),
        };
        let key = record(
            "example.test",
            RrType::DNSKEY,
            RData::Dnskey {
                flags: 257,
                protocol: 3,
                algorithm: DnssecAlgorithm(algorithm),
                public_key: public_key.clone(),
            },
        );
        let answer = a("www.example.test");
        let mut rrsig = record(
            "www.example.test",
            RrType::RRSIG,
            RData::Rrsig {
                type_covered: RrType::A,
                algorithm: DnssecAlgorithm(algorithm),
                labels: 3,
                original_ttl: 300,
                expiration: now() + 300,
                inception: now() - 60,
                key_tag: recurse_x::dnssec::key_tag(257, 3, algorithm, &public_key),
                signer: name("example.test"),
                signature: Vec::new(),
            },
        );
        let mut input = Vec::new();
        rrsig.rdata.to_wire(&mut input, None);
        answer.name.write_wire(&mut input);
        input.extend_from_slice(&[0, 1, 0, 1]);
        input.extend_from_slice(&300u32.to_be_bytes());
        input.extend_from_slice(&[0, 4, 192, 0, 2, 42]);
        let signature = match algorithm {
            8 | 10 => {
                let mut out = vec![0; 256];
                rsa.sign(
                    if algorithm == 8 {
                        &sig::RSA_PKCS1_SHA256
                    } else {
                        &sig::RSA_PKCS1_SHA512
                    },
                    &rng,
                    &input,
                    &mut out,
                )
                .unwrap();
                out
            }
            13 | 14 => ec.sign(&rng, &input).unwrap().as_ref().to_vec(),
            _ => ed.sign(&input).as_ref().to_vec(),
        };
        if let RData::Rrsig {
            signature: target, ..
        } = &mut rrsig.rdata
        {
            *target = signature;
        }
        assert_eq!(
            recurse_x::dnssec::verify_rrsig(&key, &rrsig, &[&answer], now()),
            Ok(true),
            "algorithm {algorithm}"
        );
        if let RData::Rrsig { signature, .. } = &mut rrsig.rdata {
            signature[0] ^= 1;
        }
        assert_eq!(
            recurse_x::dnssec::verify_rrsig(&key, &rrsig, &[&answer], now()),
            Ok(false),
            "algorithm {algorithm}"
        );
    }
}

#[test]
fn signature_lifetime_and_query_work_limit_bound_the_entire_chain() {
    let mut fixture = Fixture::new();
    let root = fixture
        .replies
        .get_mut(&(name("."), RrType::DNSKEY))
        .unwrap();
    root.answers[1] = fixture
        .root
        .sign_window(&root.answers[..1], now() - 60, now() + 30);
    let (resolver, stub) = fixture.run();
    assert!(
        resolver
            .resolve(&name("www.example.test"), RrType::A)
            .unwrap()
            .ttl
            <= 30
    );
    let mut cfg = resolver.config().clone();
    cfg.engine.fetch_limits.max_subqueries = 3;
    cfg.engine.qname_minimization = false;
    let limited = Resolver::new(cfg);
    let before = stub.seen.lock().unwrap().len();
    assert_eq!(
        limited
            .resolve(&name("www.example.test"), RrType::A)
            .unwrap_err()
            .kind,
        ErrorKind::Dnssec
    );
    assert!(stub.seen.lock().unwrap().len() - before <= 3);
}

#[test]
fn nsec3_iteration_limits_fail_closed_before_expensive_hashing() {
    let mut fixture = Fixture::new();
    let mut proof = nsec3("absent.example.test", "example.test", vec![RrType::TXT], 0);
    if let RData::Nsec3 { iterations, .. } = &mut proof.rdata {
        *iterations = u16::MAX;
    }
    fixture.denial(
        "absent.example.test",
        RrType::A,
        Rcode::NOERROR,
        vec![proof],
    );
    let (resolver, _stub) = fixture.run();
    assert_eq!(
        resolver
            .resolve(&name("absent.example.test"), RrType::A)
            .unwrap_err()
            .kind,
        ErrorKind::Dnssec
    );
}

#[test]
fn iana_root_defaults_include_the_2026_rollover_key() {
    let cfg = ResolverConfig::default();
    let tags: Vec<_> = cfg
        .engine
        .dnssec_trust_anchors
        .iter()
        .map(|r| match &r.rdata {
            RData::Ds {
                key_tag, digest, ..
            } => {
                assert_eq!(r.name, Name::root());
                assert_eq!(digest.len(), 32);
                *key_tag
            }
            _ => panic!("expected a DS anchor"),
        })
        .collect();
    assert_eq!(tags, [20326, 38696]);
}

#[test]
fn binary_label_suffix_cannot_impersonate_a_signer_zone() {
    let wire = [2, 1, b'a', 0];
    let (binary, _) = Name::from_wire(&wire, 0).unwrap();
    assert!(!binary.is_subdomain_of(&name("a")));
    assert!(binary.is_subdomain_of(&Name::root()));
}
