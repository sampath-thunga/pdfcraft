//! Chain building: which certificates may vouch for which (RFC 5280 §6.1, the parts that matter
//! for trust). Certificates are issued in-process with chosen extensions, so every refusal is
//! tested on its own.

use std::sync::Arc;

use pdfcraft_cos::Document;
use pdfcraft_sign::der::{self, Time, tag};
use pdfcraft_sign::pkcs12::DigitalId;
use pdfcraft_sign::x509::{Certificate, Name, build_chain, build_chain_noted};
use pdfcraft_sign::{PrivateKey, SignOptions, Status, TrustStore, signatures};

fn time(year: u32) -> Time {
    Time { year, month: 6, day: 1, hour: 12, minute: 0, second: 0 }
}

fn ext(oid: &str, value: &[u8]) -> Vec<u8> {
    der::seq(&[&der::oid(oid), &der::boolean(true), &der::octets(value)])
}

/// basicConstraints: `cA` (omitted when false, as DER does) and an optional `pathLenConstraint`.
fn basic_constraints(ca: bool, path_len: Option<u64>) -> Vec<u8> {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    if ca {
        parts.push(der::boolean(true));
    }
    if let Some(n) = path_len {
        parts.push(der::int(n));
    }
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    ext("2.5.29.19", &der::seq(&refs))
}

const DIGITAL_SIGNATURE: u8 = 0x80;
const KEY_CERT_SIGN: u8 = 0x04;

fn key_usage(bits: u8) -> Vec<u8> {
    ext("2.5.29.15", &der::tlv(tag::BIT_STRING, &[1, bits]))
}

struct Party {
    name: Name,
    key: PrivateKey,
    cert: Certificate,
}

/// A certificate for a fresh key, signed by `issuer` (or by itself).
fn issue(cn: &str, issuer: Option<&Party>, valid: (u32, u32), extensions: &[Vec<u8>]) -> Party {
    let key = PrivateKey::generate_p256().unwrap();
    let name = Name::build(cn, "", "Chain Tests", "", "US");
    let signer = issuer.map_or(&key, |i| &i.key);
    let issuer_name = issuer.map_or(&name, |i| &i.name);
    let alg = signer.preferred_digest();
    let sig_alg = signer.signature_algorithm(alg);
    let exts: Vec<&[u8]> = extensions.iter().map(Vec::as_slice).collect();
    let mut fields: Vec<Vec<u8>> = Vec::new();
    // v3 when there are extensions; with none, a v1 certificate (no version field), as old roots.
    if !exts.is_empty() {
        fields.push(der::explicit(0, &der::int(2)));
    }
    fields.extend([
        der::uint(&[1 + cn.len() as u8]),
        sig_alg.clone(),
        issuer_name.raw.clone(),
        der::seq(&[&time(valid.0).encode(), &time(valid.1).encode()]),
        name.raw.clone(),
        key.public_key().spki(),
    ]);
    if !exts.is_empty() {
        fields.push(der::explicit(3, &der::seq(&exts)));
    }
    let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    let tbs = der::seq(&refs);
    let signature = signer.sign(alg, &tbs).unwrap();
    let cert = Certificate::parse(&der::seq(&[&tbs, &sig_alg, &der::bit_string(&signature)])).unwrap();
    Party { name, key, cert }
}

const FOREVER: (u32, u32) = (2020, 2040);

fn root() -> Party {
    issue("Test Root", None, FOREVER, &[basic_constraints(true, None), key_usage(KEY_CERT_SIGN)])
}

fn ca(cn: &str, under: &Party, path_len: Option<u64>) -> Party {
    issue(cn, Some(under), FOREVER, &[basic_constraints(true, path_len), key_usage(KEY_CERT_SIGN)])
}

fn end_entity(cn: &str, under: &Party) -> Party {
    issue(cn, Some(under), FOREVER, &[basic_constraints(false, None), key_usage(DIGITAL_SIGNATURE)])
}

fn names(chain: &[&Certificate]) -> Vec<String> {
    chain.iter().map(|c| c.subject.common_name().unwrap_or_default().to_string()).collect()
}

#[test]
fn a_proper_chain_is_built() {
    let r = root();
    let i = ca("Intermediate", &r, None);
    let l = end_entity("Leaf", &i);
    let pool = [i.cert.clone(), r.cert.clone()];
    assert_eq!(names(&build_chain(&l.cert, &pool, None)), ["Leaf", "Intermediate", "Test Root"]);
    assert_eq!(names(&build_chain(&l.cert, &pool, Some(time(2026)))), ["Leaf", "Intermediate", "Test Root"]);
}

#[test]
fn an_end_entity_certificate_cannot_issue() {
    let r = root();
    let e = end_entity("Ordinary Subscriber", &r);
    // A certificate its holder made with the end-entity key.
    let forged = end_entity("Bank AG", &e);
    let pool = [e.cert.clone(), r.cert.clone()];
    let (chain, why) = build_chain_noted(&forged.cert, &pool, None);
    assert_eq!(names(&chain), ["Bank AG"], "the subscriber certificate does not vouch for what it signed");
    assert!(why.is_some_and(|w| w.contains("not a CA")), "the reason is reported");
    // Neither does one without basicConstraints (not a v1 root: it has an issuer).
    let plain = issue("No Constraints", Some(&r), FOREVER, &[]);
    let under_plain = end_entity("Under Plain", &plain);
    let pool = [plain.cert.clone(), r.cert.clone()];
    assert_eq!(names(&build_chain(&under_plain.cert, &pool, None)), ["Under Plain"]);
    // CA:TRUE does not help when keyUsage leaves out keyCertSign…
    let signing_only = issue("Signing Only CA", Some(&r), FOREVER, &[basic_constraints(true, None), key_usage(DIGITAL_SIGNATURE)]);
    let below = end_entity("Below Signing Only", &signing_only);
    let pool = [signing_only.cert.clone(), r.cert.clone()];
    assert_eq!(names(&build_chain(&below.cert, &pool, None)), ["Below Signing Only"]);
    // …and a CA with no keyUsage at all is fine.
    let any_usage = issue("Any Usage CA", Some(&r), FOREVER, &[basic_constraints(true, None)]);
    let below = end_entity("Below Any Usage", &any_usage);
    let pool = [any_usage.cert.clone(), r.cert.clone()];
    assert_eq!(names(&build_chain(&below.cert, &pool, None)), ["Below Any Usage", "Any Usage CA", "Test Root"]);
}

#[test]
fn a_path_length_constraint_limits_the_cas_below() {
    let r = root();
    let i1 = ca("Constrained", &r, Some(0));
    let i2 = ca("Sub CA", &i1, None);
    let l = end_entity("Leaf", &i2);
    let pool = [i1.cert.clone(), i2.cert.clone(), r.cert.clone()];
    // pathLen 0: no CA may follow it, so Sub CA's issuer is refused and the chain stops there.
    assert_eq!(names(&build_chain(&l.cert, &pool, None)), ["Leaf", "Sub CA"]);
    // pathLen 0 directly above the leaf is fine, and pathLen 1 allows one CA below.
    let direct = end_entity("Direct Leaf", &i1);
    assert_eq!(names(&build_chain(&direct.cert, &pool, None)), ["Direct Leaf", "Constrained", "Test Root"]);
    let i1 = ca("Constrained 1", &r, Some(1));
    let i2 = ca("Sub CA 1", &i1, None);
    let l = end_entity("Leaf 1", &i2);
    let pool = [i1.cert.clone(), i2.cert.clone(), r.cert.clone()];
    assert_eq!(names(&build_chain(&l.cert, &pool, None)), ["Leaf 1", "Sub CA 1", "Constrained 1", "Test Root"]);
}

#[test]
fn issuers_must_have_been_valid_when_it_matters() {
    let r = root();
    let old = issue("Short Lived CA", Some(&r), (2020, 2022), &[basic_constraints(true, None), key_usage(KEY_CERT_SIGN)]);
    let l = end_entity("Leaf", &old);
    let pool = [old.cert.clone(), r.cert.clone()];
    assert_eq!(names(&build_chain(&l.cert, &pool, Some(time(2021)))), ["Leaf", "Short Lived CA", "Test Root"]);
    let (chain, why) = build_chain_noted(&l.cert, &pool, Some(time(2023)));
    assert_eq!(names(&chain), ["Leaf"], "expired by then");
    assert!(why.is_some_and(|w| w.contains("not valid")));
    assert_eq!(names(&build_chain(&l.cert, &pool, Some(time(2019)))), ["Leaf"], "not yet valid");
    // With no time to judge by, nothing is refused on validity.
    assert_eq!(names(&build_chain(&l.cert, &pool, None)).len(), 3);
}

#[test]
fn an_old_v1_self_signed_root_without_constraints_still_anchors() {
    // No extensions at all: basicConstraints absent, as in v1 roots.
    let r = issue("Old V1 Root", None, FOREVER, &[]);
    assert!(r.cert.is_self_signed() && !r.cert.has_basic_constraints && r.cert.may_issue());
    let i = ca("Under V1", &r, None);
    let l = end_entity("Leaf", &i);
    let pool = [i.cert.clone(), r.cert.clone()];
    assert_eq!(names(&build_chain(&l.cert, &pool, None)), ["Leaf", "Under V1", "Old V1 Root"]);
    // A self-signed certificate that says CA:FALSE is not a root that can issue.
    let not_a_ca = issue("Self Signed Leaf", None, FOREVER, &[basic_constraints(false, None)]);
    assert!(!not_a_ca.cert.may_issue());
}

fn fixture() -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/openssl-signed.pdf", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// Sign a small PDF with `leaf`, embedding `embedded`, and validate it trusting only `anchor`.
fn verdict(leaf: Party, embedded: Vec<Certificate>, anchor: &Certificate) -> (Status, Vec<String>) {
    let id = DigitalId { key: leaf.key, certificate: leaf.cert, chain: embedded, friendly_name: None };
    let doc = Document::open(Arc::new(fixture())).unwrap();
    let opts = SignOptions { page: 0, rect: None, date: "D:20260601120000Z".into(), ..SignOptions::default() };
    let signed = pdfcraft_sign::sign(&doc, &id, &opts).unwrap();
    let trust = TrustStore { certs: vec![anchor.clone()], ..TrustStore::default() };
    let s = signatures(&Document::open(Arc::new(signed.clone())).unwrap(), &signed, &trust).into_iter().rfind(|s| s.signed).unwrap();
    (s.status, s.details)
}

#[test]
fn a_signature_chaining_through_an_ordinary_certificate_is_not_trusted() {
    let r = root();
    // The root vouches for a CA, which vouches for the signer: valid.
    let i = ca("Issuing CA", &r, None);
    let l = end_entity("Honest Signer", &i);
    let (status, details) = verdict(l, vec![i.cert.clone()], &r.cert);
    assert_eq!(status, Status::Valid, "{details:?}");
    // The root vouched for an ordinary subscriber, who signed the "signer" certificate with the
    // subscriber's own key and embedded it: the root must not vouch for that.
    let subscriber = end_entity("Ordinary Subscriber", &r);
    let forged = end_entity("Forged Identity", &subscriber);
    let (status, details) = verdict(forged, vec![subscriber.cert.clone()], &r.cert);
    assert_eq!(status, Status::Unknown, "{details:?}");
    assert!(details.iter().any(|d| d.contains("not a CA")), "{details:?}");
}

#[test]
fn a_v3_self_signed_certificate_without_constraints_is_not_a_root_that_issues() {
    // A self-signed v3 ID with no basicConstraints and no key usage (only a key identifier): it
    // may sign documents, but it may not vouch for anyone else.
    let id = issue("Self Signed V3 ID", None, FOREVER, &[ext("2.5.29.14", &der::octets(&[1, 2, 3, 4]))]);
    assert!(id.cert.is_self_signed() && !id.cert.has_basic_constraints && id.cert.version == 2);
    assert!(!id.cert.may_issue());
    let l = end_entity("Leaf", &id);
    assert_eq!(names(&build_chain(&l.cert, std::slice::from_ref(&id.cert), None)), ["Leaf"]);
}

#[test]
fn unreadable_constraint_extensions_fail_closed() {
    // keyUsage present but not a BIT STRING: no usage at all, so no keyCertSign.
    let bad_usage = ext("2.5.29.15", &[0xff, 0x00]);
    let c = issue("Bad Usage CA", Some(&root()), FOREVER, &[basic_constraints(true, None), bad_usage]);
    assert_eq!(c.cert.key_usage, Some(0));
    assert!(!c.cert.may_issue());
    // pathLenConstraint present but negative: no CA may follow, not any number.
    let negative = ext("2.5.29.19", &der::seq(&[&der::boolean(true), &der::tlv(tag::INTEGER, &[0xff])]));
    let c = issue("Negative PathLen CA", Some(&root()), FOREVER, &[negative]);
    assert!(c.cert.is_ca);
    assert_eq!(c.cert.path_len, Some(0));
    // basicConstraints present but unparsable: present, not a CA, so not an "old v1 root".
    let garbage = ext("2.5.29.19", &[0x30, 0x05, 0x01]);
    let c = issue("Garbled Constraints", None, FOREVER, &[garbage]);
    assert!(c.cert.has_basic_constraints && !c.cert.is_ca && !c.cert.may_issue());
}

/// Like `verdict`, but with a whole `TrustStore`.
fn verdict_with(leaf: Party, embedded: Vec<Certificate>, trust: &TrustStore) -> (Status, Vec<String>) {
    let id = DigitalId { key: leaf.key, certificate: leaf.cert, chain: embedded, friendly_name: None };
    let doc = Document::open(Arc::new(fixture())).unwrap();
    let opts = SignOptions { page: 0, rect: None, date: "D:20260601120000Z".into(), ..SignOptions::default() };
    let signed = pdfcraft_sign::sign(&doc, &id, &opts).unwrap();
    let s = signatures(&Document::open(Arc::new(signed.clone())).unwrap(), &signed, trust).into_iter().rfind(|s| s.signed).unwrap();
    (s.status, s.details)
}

#[test]
fn trust_sets_are_off_by_default_and_a_loaded_list_is_named_when_it_vouches() {
    use pdfcraft_sign::trust::TrustList;
    let r = root();
    let i = ca("Issuing CA", &r, None);
    let leaf = |cn: &str| end_entity(cn, &i);
    let list = TrustList::from_bytes("Test List", &r.cert.raw).unwrap();

    // Nothing is trusted unless asked for: no list, no built-in roots.
    let none = TrustStore::default();
    assert!(!none.builtin_roots && none.lists.is_empty() && none.certs.is_empty());
    let (status, details) = verdict_with(leaf("Signer A"), vec![i.cert.clone()], &none);
    assert_eq!(status, Status::Unknown, "{details:?}");

    // With the list loaded, the same signature is valid and says which list vouched.
    let with_list = TrustStore { lists: vec![list.clone()], ..TrustStore::default() };
    let (status, details) = verdict_with(leaf("Signer B"), vec![i.cert.clone()], &with_list);
    assert_eq!(status, Status::Valid, "{details:?}");
    assert!(details.iter().any(|d| d.contains("Test List")), "{details:?}");

    // The built-in roots are not these roots, so switching them on changes nothing here.
    let builtin = TrustStore { builtin_roots: true, ..TrustStore::default() };
    let (status, _) = verdict_with(leaf("Signer C"), vec![i.cert.clone()], &builtin);
    assert_eq!(status, Status::Unknown);

    // A list does not make a subscriber a CA: the forged identity stays unknown.
    let subscriber = end_entity("Ordinary Subscriber", &r);
    let forged = end_entity("Forged Identity", &subscriber);
    let (status, details) = verdict_with(forged, vec![subscriber.cert.clone()], &with_list);
    assert_eq!(status, Status::Unknown, "{details:?}");
}

#[test]
fn the_builtin_roots_only_anchor_when_switched_on() {
    // Trust is decided by `source_of`, which is what validation uses.
    let first = pdfcraft_sign::trust::builtin_roots().first().unwrap();
    let off = TrustStore::default();
    assert_eq!(off.source_of(first), None);
    let on = TrustStore { builtin_roots: true, ..TrustStore::default() };
    assert_eq!(on.source_of(first), Some(pdfcraft_sign::TrustSource::BuiltinRoots));
    // The user's own list wins when both apply.
    let both = TrustStore { certs: vec![first.clone()], builtin_roots: true, ..TrustStore::default() };
    assert_eq!(both.source_of(first), Some(pdfcraft_sign::TrustSource::User));
}

// ── what a trust set vouches for ───────────────────────────────────────────────────────────────
// The built-in roots and loaded lists trust a CA for everything it issues, and most of those CAs
// issue TLS certificates. A certificate that is not meant for signing documents is not vouched for
// by them; the user's own trusted certificates are their decision and are never second-guessed.

fn extended_key_usage(purposes: &[&str]) -> Vec<u8> {
    let oids: Vec<Vec<u8>> = purposes.iter().map(|p| der::oid(p)).collect();
    let refs: Vec<&[u8]> = oids.iter().map(Vec::as_slice).collect();
    ext("2.5.29.37", &der::seq(&refs))
}

/// An extended key usage whose entries are the given encodings (they need not be OIDs).
fn extended_key_usage_raw(entries: &[Vec<u8>]) -> Vec<u8> {
    let refs: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
    ext("2.5.29.37", &der::seq(&refs))
}

const SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
const EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";
const ADOBE_DOCUMENT_SIGNING: &str = "1.2.840.113583.1.1.5";
const ANY_EXTENDED_KEY_USAGE: &str = "2.5.29.37.0";
const NON_REPUDIATION: u8 = 0x40;

#[test]
fn a_trust_set_does_not_vouch_for_a_certificate_that_is_not_meant_for_signing_documents() {
    use pdfcraft_sign::trust::TrustList;
    let r = root();
    let i = ca("Issuing CA", &r, None);
    let with_list = TrustStore { lists: vec![TrustList::from_bytes("Test List", &r.cert.raw).unwrap()], ..TrustStore::default() };
    let leaf = |cn: &str, usage: u8, purposes: Option<&[&str]>| {
        let mut exts = vec![basic_constraints(false, None), key_usage(usage)];
        exts.extend(purposes.map(extended_key_usage));
        issue(cn, Some(&i), FOREVER, &exts)
    };
    let verdict_of = |l: Party, trust: &TrustStore| verdict_with(l, vec![i.cert.clone()], trust).0;

    // An ordinary TLS server certificate of the trusted CA: the CA vouches for it as a web site,
    // not as someone who signs documents.
    let tls = || leaf("www.example.com", DIGITAL_SIGNATURE, Some(&[SERVER_AUTH, CLIENT_AUTH]));
    let (status, details) = verdict_with(tls(), vec![i.cert.clone()], &with_list);
    assert_eq!(status, Status::Unknown, "{details:?}");
    assert!(details.iter().any(|d| d.contains("not meant for signing documents")), "{details:?}");
    // The same certificate is fine when the user trusts the root themselves: their decision.
    let mine = TrustStore { certs: vec![r.cert.clone()], ..TrustStore::default() };
    assert_eq!(verdict_of(tls(), &mine), Status::Valid);
    // An extended key usage that can't be read allows nothing (it used to allow everything).
    let garbled =
        issue("Garbled EKU", Some(&i), FOREVER, &[basic_constraints(false, None), key_usage(DIGITAL_SIGNATURE), ext("2.5.29.37", &[0xff, 0x00])]);
    assert_eq!(verdict_of(garbled, &with_list), Status::Unknown);
    // A key usage without digitalSignature or nonRepudiation is no signing certificate either.
    assert_eq!(verdict_of(leaf("Key Agreement", 0x08, None), &with_list), Status::Unknown);

    // What is meant for signing documents is vouched for.
    for (what, l) in [
        ("e-mail protection", leaf("Mail", DIGITAL_SIGNATURE, Some(&[CLIENT_AUTH, EMAIL_PROTECTION]))),
        ("Adobe document signing", leaf("Adobe", NON_REPUDIATION, Some(&[ADOBE_DOCUMENT_SIGNING]))),
        ("any purpose", leaf("Any", DIGITAL_SIGNATURE, Some(&[ANY_EXTENDED_KEY_USAGE]))),
        ("no extended key usage", leaf("Unrestricted", DIGITAL_SIGNATURE, None)),
    ] {
        let (status, details) = verdict_with(l, vec![i.cert.clone()], &with_list);
        assert_eq!(status, Status::Valid, "{what}: {details:?}");
    }
}

#[test]
fn certificate_purposes_are_read_from_key_usage_and_extended_key_usage() {
    let r = root();
    let make = |usage: Option<u8>, purposes: Option<&[&str]>| {
        let mut exts = vec![basic_constraints(false, None)];
        exts.extend(usage.map(key_usage));
        exts.extend(purposes.map(extended_key_usage));
        issue("Purpose", Some(&r), FOREVER, &exts).cert
    };
    assert!(make(None, None).may_sign_documents(), "no restriction at all");
    assert!(make(Some(DIGITAL_SIGNATURE), None).may_sign_documents());
    assert!(make(Some(NON_REPUDIATION), None).may_sign_documents());
    assert!(!make(Some(KEY_CERT_SIGN), None).may_sign_documents(), "a CA-only key");
    assert!(!make(None, Some(&[SERVER_AUTH])).may_sign_documents());
    assert!(!make(Some(DIGITAL_SIGNATURE), Some(&[SERVER_AUTH])).may_sign_documents());
    assert!(make(None, Some(&[SERVER_AUTH, EMAIL_PROTECTION])).may_sign_documents());
    // Every purpose that names signing documents.
    for purpose in [ADOBE_DOCUMENT_SIGNING, "1.3.6.1.5.5.7.3.36", "1.3.6.1.4.1.311.10.3.12"] {
        assert!(make(None, Some(&[SERVER_AUTH, purpose])).may_sign_documents(), "{purpose}");
    }
    // An extension that is present restricts the key even when it doesn't parse: an unreadable one
    // allows no purpose at all, never every purpose (fail closed, as for keyUsage and basicConstraints).
    let garbled = |ext_oid: &str| issue("Garbled", Some(&r), FOREVER, &[basic_constraints(false, None), ext(ext_oid, &[0xff, 0x00])]).cert;
    let bad_eku = garbled("2.5.29.37");
    assert_eq!(bad_eku.extended_key_usage.as_deref(), Some(&[][..]));
    assert!(!bad_eku.may_sign_documents() && !bad_eku.may_timestamp());
    // A purpose that isn't an OID grants nothing either.
    let not_an_oid = issue("Not An OID", Some(&r), FOREVER, &[extended_key_usage_raw(&[der::int(1)])]).cert;
    assert!(!not_an_oid.may_sign_documents());
    // A time-stamp authority has to say so (RFC 3161 §2.3), unlike a signer.
    assert!(!make(None, None).may_timestamp());
    assert!(!make(None, Some(&[EMAIL_PROTECTION])).may_timestamp());
    assert!(!make(None, Some(&[ANY_EXTENDED_KEY_USAGE])).may_timestamp());
    assert!(make(Some(DIGITAL_SIGNATURE), Some(&["1.3.6.1.5.5.7.3.8"])).may_timestamp());
}
