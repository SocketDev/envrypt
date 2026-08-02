//! Tier-1 spec conformance: corpus fidelity (shape invariants).
//!
//! `conformance/cases/spec/spec.json` is the normative, frozen 88-case corpus
//! (88/88 is release-blocking). The actual 88-case parse assertion against
//! envrypt's library pipeline lives in `parser_conformance.rs`
//! (`MapSource::ParsesTo`). Crypto and interop coverage lives in
//! `crates/envrypt/tests`, driven by checked-in vectors.

use envrypt_conformance::{load_spec_cases, spec_cases_path, Encoding};

/// Shape invariants of the frozen corpus: exactly 88 cases, unique ids, 11 MACHINE
/// env-precondition cases, and the two 9xx encoding cases.
#[test]
fn tier1_corpus_shape() {
    let cases = load_spec_cases(&spec_cases_path()).expect("spec.json loads");
    assert_eq!(cases.len(), 88, "tier 1 is exactly the 88 spec cases");
    assert_eq!(cases.first().unwrap().id, "101_BASIC");
    assert_eq!(cases.last().unwrap().id, "902_UTF16LE");

    let mut ids: Vec<&str> = cases.iter().map(|c| c.id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 88, "case ids are unique");

    let machine: Vec<&str> = cases
        .iter()
        .filter(|c| !c.env.is_empty())
        .map(|c| c.id.as_str())
        .collect();
    assert_eq!(
        machine,
        [
            "103_MACHINE",
            "502_EXPAND_MACHINE",
            "517_EXPAND_DEFAULT",
            "518_EXPAND_DEFAULT2",
            "519_EXPAND_DEFAULT_NESTED",
            "520_EXPAND_DEFAULT_NESTED2",
            "521_EXPAND_DEFAULT_NESTED_TWICE",
            "522_EXPAND_DEFAULT_NESTED_TWICE2",
            "523_EXPAND_DEFAULT_SPECIAL_CHARACTERS",
            "524_EXPAND_DEFAULT_SPECIAL_CHARACTERS2",
            "526_EXPAND_UNDEFINED_NESTED",
        ],
        "exactly the 11 MACHINE-precondition cases"
    );
    for id in machine {
        let case = cases.iter().find(|c| c.id == id).unwrap();
        assert_eq!(
            case.env,
            vec![("MACHINE".to_string(), "machine".to_string())],
            "{id}: the only env precondition in the suite is MACHINE=machine"
        );
    }

    let encodings: Vec<(&str, Encoding)> = cases
        .iter()
        .filter(|c| c.encoding != Encoding::Utf8)
        .map(|c| (c.id.as_str(), c.encoding))
        .collect();
    assert_eq!(
        encodings,
        [
            ("901_LATIN1", Encoding::Latin1),
            ("902_UTF16LE", Encoding::Utf16Le),
        ],
        "exactly the two 9xx encoding cases"
    );
}
