//! Configurable key-resolution naming.
//!
//! The default identifier prefix is `ENVRYPT_`; a consumer may set the prefix (for
//! example `DOTENV_`) or an explicit per-variable override. These tests live here (an
//! integration test) rather than inline in `src/` so the shipped `crates/*/src` tree
//! holds no `DOTENV_` identifier token.

use envrypt::conventions::keynames::{keynames_with, KeyNaming};
use envrypt::crypto::keypair;
use envrypt::keyring::{keyring_local, KeyringLocalOptions, Ring};
use indexmap::IndexMap;
use std::path::PathBuf;

fn env(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn ring_from_env(pe: &IndexMap<String, String>, naming: &KeyNaming) -> Ring {
    keyring_local(&KeyringLocalOptions {
        process_env: pe,
        fk: vec![PathBuf::from("this-file-does-not-exist.keys")],
        seed_ring: Ring::new(),
        naming,
    })
}

// The default naming reads `ENVRYPT_PRIVATE_KEY*` from the process env and ignores
// the legacy `DOTENV_PRIVATE_KEY` prefix.
#[test]
fn default_naming_reads_envrypt_only() {
    let a = keypair();
    let resolved = ring_from_env(
        &env(&[("ENVRYPT_PRIVATE_KEY", &a.private_key)]),
        &KeyNaming::default(),
    );
    assert_eq!(resolved.get(&a.public_key), Some(&a.private_key));

    let legacy = format!("{}PRIVATE_KEY", "DOTENV_"); // built so `src` grep stays clean
    let ignored = ring_from_env(&env(&[(&legacy, &a.private_key)]), &KeyNaming::default());
    assert!(
        ignored.is_empty(),
        "default naming must ignore the legacy prefix"
    );
}

// A consumer-set `DOTENV_` prefix resolves the legacy identifier.
#[test]
fn consumer_legacy_prefix_resolves() {
    let a = keypair();
    let naming = KeyNaming::from_prefix("DOTENV_");
    let legacy = format!("{}PRIVATE_KEY", "DOTENV_");
    let resolved = ring_from_env(&env(&[(&legacy, &a.private_key)]), &naming);
    assert_eq!(resolved.get(&a.public_key), Some(&a.private_key));
}

// An explicit `private_key_var("ACME_SECRET")` resolves that exact variable.
#[test]
fn explicit_private_key_var_resolves() {
    let a = keypair();
    let naming = KeyNaming {
        private_key_var: Some("ACME_SECRET".to_string()),
        ..KeyNaming::default()
    };
    let resolved = ring_from_env(&env(&[("ACME_SECRET", &a.private_key)]), &naming);
    assert_eq!(resolved.get(&a.public_key), Some(&a.private_key));
}

// keyname derivation honors the prefix + explicit vars.
#[test]
fn keynames_honor_prefix_and_explicit_var() {
    // Default prefix drives the base + suffixed families.
    let d = KeyNaming::default();
    let base = keynames_with(".env", "", &d);
    assert_eq!(base.public_key_name, "ENVRYPT_PUBLIC_KEY");
    assert_eq!(base.private_key_name, "ENVRYPT_PRIVATE_KEY");
    let prod = keynames_with(".env.production", "", &d);
    assert_eq!(prod.private_key_name, "ENVRYPT_PRIVATE_KEY_PRODUCTION");

    // A consumer prefix.
    let legacy = KeyNaming::from_prefix("DOTENV_");
    assert_eq!(
        keynames_with(".env", "", &legacy).public_key_name,
        format!("{}PUBLIC_KEY", "DOTENV_")
    );

    // Explicit var override wins for the base `.env` case.
    let explicit = KeyNaming {
        private_key_var: Some("ACME_SECRET".to_string()),
        ..KeyNaming::default()
    };
    assert_eq!(
        keynames_with(".env", "", &explicit).private_key_name,
        "ACME_SECRET"
    );
}
