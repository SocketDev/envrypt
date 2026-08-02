//! Wire-format freeze tripwire. `conformance/vectors/interop/interop.json`
//! holds one vector per supported wire format — the frozen v1 read formats
//! (`encrypted:` ECIES and `locked:` v1) and the native v3 write format
//! (recipient + passphrase) — and every vector MUST keep decrypting/unlocking
//! under envrypt forever. If a change reddens this test, a wire format was
//! mutated: that is a stop-the-line bug, never a golden file to update.
//!
//! The corpus is minted **in-repo**: the `#[ignore]`d
//! [`regenerate_interop_corpus`] test rewrites the JSON with fresh keys and
//! fresh plaintext randomness (`cargo test -p envrypt --test interop_corpus
//! regenerate_interop_corpus -- --ignored`). Layout specs:
//! `docs/envrypt/crypto-formats.md` §1–§2 (v1) and `docs/envrypt/crypto-v3.md`
//! (v3).

use envrypt::crypto::{decrypt, derive, ENCRYPTED_PREFIX};
use envrypt::crypto_v3::{decrypt_entry, decrypt_v3, unlock_entry, unlock_v3};
use envrypt::services::lock::unlock_value;
use serde_json::{json, Value};

const CORPUS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/vectors/interop/interop.json"
);

fn corpus() -> Value {
    let raw =
        std::fs::read_to_string(CORPUS_PATH).expect("conformance/vectors/interop/interop.json");
    serde_json::from_str(&raw).expect("interop.json parses")
}

fn field<'a>(v: &'a Value, name: &str) -> &'a str {
    v[name]
        .as_str()
        .unwrap_or_else(|| panic!("vector field {name} present"))
}

/// v1 `encrypted:` ECIES values keep decrypting — both through the primitive
/// reader and through the version-routed entry point the load pipeline uses
/// (which must leave v1 payloads on the v1 path).
#[test]
fn v1_encrypted_values_keep_decrypting() {
    let doc = corpus();
    let entries = doc["encrypted_v1"].as_array().expect("encrypted_v1 array");
    assert!(
        entries.len() >= 8,
        "expected >= 8 v1 encrypted vectors, got {}",
        entries.len()
    );
    for v in entries {
        let name = field(v, "name");
        let public_key = field(v, "publicKey");
        let private_key = field(v, "privateKey");
        let plaintext = field(v, "plaintext");
        let value = field(v, "value");

        assert!(
            value.starts_with(ENCRYPTED_PREFIX),
            "encrypted_v1[{name}] carries the encrypted: prefix"
        );
        // key pairing sanity
        assert_eq!(
            derive(private_key).unwrap(),
            public_key,
            "encrypted_v1[{name}]: derive(privateKey) == publicKey"
        );
        // primitive v1 reader
        let got = decrypt(private_key, value, true)
            .unwrap_or_else(|e| panic!("encrypted_v1[{name}] decrypt failed: {e}"));
        assert_eq!(got, plaintext, "encrypted_v1[{name}] plaintext");
        // version-routed entry point (the name is ignored on the v1 path)
        let got = decrypt_entry(private_key, value, "ANY_NAME")
            .unwrap_or_else(|e| panic!("encrypted_v1[{name}] routed decrypt failed: {e}"));
        assert_eq!(got, plaintext, "encrypted_v1[{name}] via decrypt_entry");
    }
}

/// v1 `locked:` values keep unlocking — through the v1 reader and through the
/// version-routed entry point.
#[test]
fn v1_locked_values_keep_unlocking() {
    let doc = corpus();
    let entries = doc["locked_v1"].as_array().expect("locked_v1 array");
    assert!(
        entries.len() >= 4,
        "expected >= 4 v1 locked vectors, got {}",
        entries.len()
    );
    for v in entries {
        let name = field(v, "name");
        let public_key = field(v, "publicKey");
        let private_key_plaintext = field(v, "privateKeyPlaintext");
        let passphrase = field(v, "passphrase");
        let value = field(v, "value");

        // wire shape: locked:<pubhex>:<base64url payload>
        let mut parts = value.splitn(3, ':');
        assert_eq!(parts.next(), Some("locked"), "locked_v1[{name}] prefix");
        assert_eq!(
            parts.next(),
            Some(public_key),
            "locked_v1[{name}] embedded public key"
        );
        assert!(
            parts.next().is_some_and(|p| !p.is_empty()),
            "locked_v1[{name}] payload present"
        );

        let got = unlock_value(value, passphrase)
            .unwrap_or_else(|| panic!("locked_v1[{name}] unlock returned None"));
        assert_eq!(got, private_key_plaintext, "locked_v1[{name}] plaintext");
        // version-routed entry point (the name is ignored on the v1 path)
        let got = unlock_entry(value, passphrase, "ANY_NAME")
            .unwrap_or_else(|| panic!("locked_v1[{name}] routed unlock returned None"));
        assert_eq!(
            got, private_key_plaintext,
            "locked_v1[{name}] via unlock_entry"
        );
    }
}

/// v3 `encrypted:` values decrypt under their sealed variable name — and stay
/// sealed under any other name.
#[test]
fn v3_encrypted_values_decrypt() {
    let doc = corpus();
    let entries = doc["encrypted_v3"].as_array().expect("encrypted_v3 array");
    assert!(
        entries.len() >= 8,
        "expected >= 8 v3 encrypted vectors, got {}",
        entries.len()
    );
    for v in entries {
        let name = field(v, "name");
        let private_key = field(v, "privateKey");
        let plaintext = field(v, "plaintext");
        let var_name = field(v, "varName");
        let value = field(v, "value");

        assert!(
            value.starts_with(ENCRYPTED_PREFIX),
            "encrypted_v3[{name}] carries the encrypted: prefix"
        );
        let got = decrypt_v3(private_key, value, var_name)
            .unwrap_or_else(|e| panic!("encrypted_v3[{name}] decrypt failed: {e}"));
        assert_eq!(got, plaintext, "encrypted_v3[{name}] plaintext");
        // the routed entry point takes the v3 path
        let got = decrypt_entry(private_key, value, var_name)
            .unwrap_or_else(|e| panic!("encrypted_v3[{name}] routed decrypt failed: {e}"));
        assert_eq!(got, plaintext, "encrypted_v3[{name}] via decrypt_entry");
        // name binding: a different variable name keeps the value sealed
        assert!(
            decrypt_v3(private_key, value, "SOME_OTHER_NAME").is_err(),
            "encrypted_v3[{name}] must stay sealed under another name"
        );
    }
}

/// v3 `locked:` values unlock under their sealed variable name, honoring the
/// Argon2id params carried in each vector's header.
#[test]
fn v3_locked_values_unlock() {
    let doc = corpus();
    let entries = doc["locked_v3"].as_array().expect("locked_v3 array");
    assert!(
        entries.len() >= 4,
        "expected >= 4 v3 locked vectors, got {}",
        entries.len()
    );
    for v in entries {
        let name = field(v, "name");
        let public_key = field(v, "publicKey");
        let private_key_plaintext = field(v, "privateKeyPlaintext");
        let passphrase = field(v, "passphrase");
        let var_name = field(v, "varName");
        let value = field(v, "value");

        assert!(
            value.starts_with(&format!("locked:{public_key}:")),
            "locked_v3[{name}] frame echoes the public key"
        );
        // one unlock per vector (the default-params vector runs the full-cost
        // KDF; routing equivalence is pinned by the module's unit tests)
        let got = unlock_v3(value, passphrase, var_name)
            .unwrap_or_else(|e| panic!("locked_v3[{name}] unlock failed: {e}"));
        assert_eq!(got, private_key_plaintext, "locked_v3[{name}] plaintext");
    }
}

// ---------------------------------------------------------------------------
// regeneration (ignored; run explicitly to mint a fresh corpus)
// ---------------------------------------------------------------------------

/// The plaintext categories the encrypted vectors cover.
const PLAINTEXTS: &[(&str, &str, &str)] = &[
    ("empty", "EMPTY_VALUE", ""),
    ("ascii", "SERVICE_TOKEN", "fresh ascii plaintext 42"),
    ("unicode", "GREETING", "naïve café ☕ 日本語 🚀 Ω"),
    (
        "control_chars",
        "MULTILINE_PEMISH",
        "line one\nline two\r\ntab\there\u{7}bell",
    ),
    (
        "quotes",
        "SHELLY",
        "d0uble \"quotes\" 'singles' `ticks` ${expansion} \\slash",
    ),
    (
        "structured",
        "CONFIG_JSON",
        "{\"svc\":{\"port\":8443},\"tags\":[\"a\",\"b\"]}",
    ),
    ("single_char", "FLAG", "Z"),
];

/// Rewrite `conformance/vectors/interop/interop.json` with freshly generated
/// keys, plaintexts, and randomness (deterministic structure, fresh bytes).
///
/// ```sh
/// cargo test -p envrypt --test interop_corpus regenerate_interop_corpus -- --ignored
/// ```
#[test]
#[ignore = "regenerates the checked-in corpus; run explicitly"]
fn regenerate_interop_corpus() {
    use envrypt::crypto::{encrypt_with_key, keypair, parse_public_key};
    use envrypt::crypto_v3::{encrypt_v3, keypair_v3, lock_v3, Argon2Params};

    // -- v1 encrypted: the crate's own legacy writer over fresh secp256k1 keys.
    let mut encrypted_v1 = Vec::new();
    for (name, _, plaintext) in PLAINTEXTS {
        let kp = keypair();
        let recipient = parse_public_key(&kp.public_key).expect("fresh key parses");
        encrypted_v1.push(json!({
            "name": name,
            "publicKey": kp.public_key,
            "privateKey": kp.private_key,
            "plaintext": plaintext,
            "value": encrypt_with_key(&recipient, plaintext, true),
        }));
    }
    {
        let kp = keypair();
        let recipient = parse_public_key(&kp.public_key).expect("fresh key parses");
        let long = "long-".repeat(128);
        encrypted_v1.push(json!({
            "name": "long",
            "publicKey": kp.public_key,
            "privateKey": kp.private_key,
            "plaintext": long,
            "value": encrypt_with_key(&recipient, &long, true),
        }));
    }

    // -- v1 locked: the test-support v1 writer (CRYPTO-FORMATS §2 byte-for-byte).
    let mut locked_v1 = Vec::new();
    for (name, passphrase) in [
        ("simple", "hunter2 the sequel"),
        ("spaces", "battery horse correct staple"),
        ("symbols", "p@55w0rd!#%^&*()_+-= §±"),
        (
            "long_passphrase",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ),
    ] {
        let kp = keypair();
        locked_v1.push(json!({
            "name": name,
            "publicKey": kp.public_key,
            "privateKeyPlaintext": kp.private_key,
            "passphrase": passphrase,
            "value": test_support::lock_value_v1(&kp.public_key, &kp.private_key, passphrase),
        }));
    }

    // -- v3 encrypted: recipient mode over fresh X25519 keys, name-bound.
    let mut encrypted_v3 = Vec::new();
    for (name, var_name, plaintext) in PLAINTEXTS {
        let kp = keypair_v3();
        encrypted_v3.push(json!({
            "name": name,
            "publicKey": kp.public_key,
            "privateKey": kp.private_key,
            "varName": var_name,
            "plaintext": plaintext,
            "value": encrypt_v3(&kp.public_key, plaintext, var_name).expect("fresh key encrypts"),
        }));
    }
    {
        let kp = keypair_v3();
        let long = "gnol-".repeat(128);
        encrypted_v3.push(json!({
            "name": "long",
            "publicKey": kp.public_key,
            "privateKey": kp.private_key,
            "varName": "LONG_VALUE",
            "plaintext": long,
            "value": encrypt_v3(&kp.public_key, &long, "LONG_VALUE").expect("fresh key encrypts"),
        }));
    }

    // -- v3 locked: passphrase mode; three reduced-cost param sets plus the
    // shipped defaults (t=3, m=65536 KiB, p=1).
    let mut locked_v3 = Vec::new();
    for (name, passphrase, params) in [
        (
            "reduced_t1",
            "open sesame 3",
            Argon2Params {
                t_cost: 1,
                m_cost: 8192,
                p: 1,
            },
        ),
        (
            "reduced_t2",
            "unicode pass ✓ φράση",
            Argon2Params {
                t_cost: 2,
                m_cost: 8192,
                p: 1,
            },
        ),
        (
            "reduced_lanes",
            "two lanes here",
            Argon2Params {
                t_cost: 1,
                m_cost: 16384,
                p: 2,
            },
        ),
        ("defaults", "hunter2 the third", Argon2Params::default()),
    ] {
        let kp = keypair_v3();
        locked_v3.push(json!({
            "name": name,
            "publicKey": kp.public_key,
            "privateKeyPlaintext": kp.private_key,
            "passphrase": passphrase,
            "varName": "ENVRYPT_PRIVATE_KEY",
            "argon2": { "t_cost": params.t_cost, "m_cost": params.m_cost, "p": params.p },
            "value": lock_v3(&kp.public_key, &kp.private_key, passphrase, "ENVRYPT_PRIVATE_KEY", &params)
                .expect("fresh key locks"),
        }));
    }

    let doc = json!({
        "_meta": {
            "description": "Wire-format freeze corpus: one vector set per supported value layout — v1 encrypted:/locked: (frozen read formats) and v3 encrypted:/locked: (the native write format). Every vector MUST keep decrypting/unlocking under envrypt forever; the tripwire is crates/envrypt/tests/interop_corpus.rs.",
            "note": "Generated by this repo's own generator: `cargo test -p envrypt --test interop_corpus regenerate_interop_corpus -- --ignored` rewrites this file with fresh keys, plaintexts, and randomness. Regenerating changes the bytes; the corpus contract (decrypt -> plaintext) is invariant.",
            "formats": {
                "encrypted_v1": "docs/envrypt/crypto-formats.md §1 — secp256k1 ECIES + AES-256-GCM, base64 std",
                "locked_v1": "docs/envrypt/crypto-formats.md §2 — scrypt N=2^14/r=8/p=1 + AES-256-GCM, base64url",
                "encrypted_v3": "docs/envrypt/crypto-v3.md — X25519 + HKDF-SHA256 + XChaCha20-Poly1305, name-bound AAD, key commitment",
                "locked_v3": "docs/envrypt/crypto-v3.md — Argon2id + XChaCha20-Poly1305, name-bound AAD, key commitment"
            }
        },
        "encrypted_v1": encrypted_v1,
        "locked_v1": locked_v1,
        "encrypted_v3": encrypted_v3,
        "locked_v3": locked_v3,
    });

    let mut serialized = serde_json::to_string_pretty(&doc).expect("corpus serializes");
    serialized.push('\n');
    std::fs::write(CORPUS_PATH, serialized).expect("write interop.json");
}
