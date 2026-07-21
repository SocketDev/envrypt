//! Golden crypto vectors from `conformance/vectors/crypto.json`. The `decrypt`
//! entries are frozen `encrypted:` ciphertexts that must decrypt to their recorded
//! plaintext; the `errors` entries pin `decrypt_key_value`'s error taxonomy (code,
//! message, help, messageWithHelp) exactly.
//!
//! Encryption is randomized (a fresh ephemeral key and nonce per value), so the
//! encrypt direction is checked by round trip, not by comparing ciphertext bytes.
//! The `encrypted:` ECIES layout is frozen in docs/envrypt/crypto-formats.md §1.

use envrypt::crypto::{decrypt, decrypt_key_value, derive, encrypt, ENCRYPTED_PREFIX};
use serde_json::Value;

const VECTORS_PATH: &str = concat!(
  env!("CARGO_MANIFEST_DIR"),
  "/../../conformance/vectors/crypto.json"
);

fn vectors() -> Value {
  let raw = std::fs::read_to_string(VECTORS_PATH).expect("conformance/vectors/crypto.json");
  serde_json::from_str(&raw).expect("crypto.json parses")
}

#[test]
fn golden_encrypted_vectors_decrypt_to_plaintext() {
  let doc = vectors();
  let entries = doc["decrypt"].as_array().expect("decrypt array");
  assert!(entries.len() >= 20, "expected ≥ 20 decrypt vectors");
  for v in entries {
    let name = v["name"].as_str().unwrap();
    let private_key = v["privateKey"].as_str().unwrap();
    let plaintext = v["plaintext"].as_str().unwrap();
    let ciphertext = v["ciphertext"].as_str().unwrap();

    // low-level decrypt
    let got = decrypt(private_key, ciphertext, true)
      .unwrap_or_else(|e| panic!("decrypt({name}) failed: {e}"));
    assert_eq!(got, plaintext, "vector {name}");

    // the keyed decrypt_key_value helper
    let got = decrypt_key_value("KEY", ciphertext, "DOTENV_PRIVATE_KEY", Some(private_key))
      .unwrap_or_else(|e| panic!("decrypt_key_value({name}) failed: {e}"));
    assert_eq!(got, plaintext, "vector {name} via decrypt_key_value");

    // key pairing sanity: derive(privateKey) == publicKey where recorded
    if let Some(public_key) = v["publicKey"].as_str() {
      assert_eq!(
        derive(private_key).unwrap(),
        public_key,
        "derive for {name}"
      );

      // Round trip against the same recorded keypair (cross-format vectors
      // live in interop_corpus.rs).
      let reencrypted = encrypt(public_key, plaintext, true)
        .unwrap_or_else(|e| panic!("encrypt({name}) failed: {e}"));
      assert!(reencrypted.starts_with(ENCRYPTED_PREFIX));
      assert_eq!(
        decrypt(private_key, &reencrypted, true).unwrap(),
        plaintext,
        "re-encrypt round-trip for {name}"
      );
    }
  }
}

// Each error vector records the exact code, message, help, and messageWithHelp
// `decrypt_key_value` must produce for a failing input.
#[test]
fn decrypt_key_value_error_vectors() {
  let doc = vectors();
  let entries = doc["errors"].as_array().expect("errors array");
  assert!(entries.len() >= 10, "expected ≥ 10 error vectors");
  for v in entries {
    let name = v["name"].as_str().unwrap();
    let key = v["key"].as_str().unwrap();
    let value = v["value"].as_str().unwrap();
    let private_key_name = v["privateKeyName"].as_str().unwrap();
    let private_key = v["privateKey"].as_str(); // JSON null → None

    let error = decrypt_key_value(key, value, private_key_name, private_key)
      .expect_err(&format!("vector {name} must fail"));

    assert_eq!(
      error.code.expect("coded error").as_str(),
      v["code"].as_str().unwrap(),
      "code for {name}"
    );
    assert_eq!(
      error.message,
      v["message"].as_str().unwrap(),
      "message for {name}"
    );
    assert_eq!(error.help.as_deref(), v["help"].as_str(), "help for {name}");
    assert_eq!(
      error.message_with_help(),
      v["messageWithHelp"].as_str().unwrap(),
      "messageWithHelp for {name}"
    );
  }
}
