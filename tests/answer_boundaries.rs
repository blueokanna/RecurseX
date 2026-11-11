#![cfg(feature = "std")]
use recurse_x::engine::{classify_response, ResponseKind};
use recurse_x::qtype::RrClass;
use recurse_x::query::QueryKey;
use recurse_x::rrset::RrSet;
use recurse_x::{Message, Name, RData, Record, Resolver, ResolverConfig, RrType};

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}
fn address(owner: &str) -> Record {
    Record {
        name: name(owner),
        rr_type: RrType::A,
        class: RrClass::IN,
        ttl: 60,
        rdata: RData::A("192.0.2.1".parse().unwrap()),
    }
}
fn key() -> QueryKey {
    QueryKey {
        name: name("www.example.test"),
        rr_type: RrType::A,
        class: RrClass::IN,
        ecs: None,
        want_dnssec: false,
        cd: false,
    }
}

#[test]
fn mixed_rrset_owners_and_classes_are_rejected() {
    assert!(RrSet::from_records(vec![address("a.test"), address("b.test")], 300).is_err());
    let mut wrong_class = address("a.test");
    wrong_class.class = RrClass::CH;
    assert!(RrSet::from_records(vec![address("a.test"), wrong_class], 300).is_err());
}

#[test]
fn alien_referral_and_wrong_class_answer_do_not_advance_recursion() {
    let mut response = Message::new(1);
    response.flags.qr = true;
    let mut wrong = address("www.example.test");
    wrong.class = RrClass::CH;
    response.answers.push(wrong);
    response.authorities.push(Record {
        name: name("unrelated.test"),
        rr_type: RrType::NS,
        class: RrClass::IN,
        ttl: 60,
        rdata: RData::Ns(name("ns.unrelated.test")),
    });
    assert!(matches!(
        classify_response(&response, &key().name, RrType::A, &name("test")),
        ResponseKind::Empty
    ));
}

#[test]
fn non_internet_question_never_uses_local_hosts_or_network() {
    let resolver = Resolver::new(ResolverConfig::default());
    let mut question = key();
    question.class = RrClass::CH;
    assert_eq!(
        resolver.resolve_key(&question).unwrap_err().kind,
        recurse_x::ErrorKind::Policy
    );
}

#[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
#[test]
fn forward_admission_follows_alias_but_discards_unrelated_records() {
    let mut response = Message::new(1);
    response.flags.qr = true;
    response.answers = vec![
        address("unrelated.test"),
        address("target.test"),
        Record {
            name: key().name,
            rr_type: RrType::CNAME,
            class: RrClass::IN,
            ttl: 60,
            rdata: RData::Cname(name("target.test")),
        },
    ];
    let resolution = recurse_x::forward::response_to_resolution(&key(), &response);
    assert_eq!(resolution.answers.len(), 2);
    assert_eq!(resolution.answers[0].rr_type, RrType::CNAME);
    assert_eq!(resolution.answers[1].name, name("target.test"));
}

#[test]
fn nxdomain_alias_is_followed_instead_of_denying_its_existing_owner() {
    let mut response = Message::new(1);
    response.flags.qr = true;
    response.flags.rcode = recurse_x::qtype::Rcode::NXDOMAIN;
    response.answers.push(Record {
        name: key().name,
        rr_type: RrType::CNAME,
        class: RrClass::IN,
        ttl: 60,
        rdata: RData::Cname(name("missing.test")),
    });
    assert!(matches!(
        classify_response(&response, &key().name, RrType::A, &Name::root()),
        ResponseKind::Cname { .. }
    ));
}
