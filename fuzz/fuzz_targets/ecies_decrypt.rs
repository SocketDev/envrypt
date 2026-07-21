#![no_main]
//! FUZZ target `ecies_decrypt` (WP-21, doc 11 §7.2 target 2).
//!
//! Three lanes over one raw byte buffer, all against a FIXED, deterministic test
//! keypair (never random):
//!
//! (a) fuzz bytes as the RAW post-base64 wire payload
//!     (`eph_pub(65) || nonce(16) || tag(16) || ct`) → `ecies_decrypt` directly
//!     (via the `--cfg fuzzing` `fuzz_decrypt_wire_payload` seam, which skips the
//!     base64 layer that a lenient decoder would otherwise gate the byte space on).
//! (b) fuzz bytes as a `String` fed through the public `decrypt` entry, both as-is
//!     and with an `encrypted:` prefix forced on (so the base64 + crypto branch is
//!     always taken).
//! (c) round-trip property: `decrypt(encrypt(pt)) == pt` for arbitrary (valid-UTF-8)
//!     plaintext bytes.
//!
//! Assertions: never panics; every FAILURE maps to exactly one of the FOUR
//! doc 03 §4 error conditions (INVALID_PRIVATE_KEY / WRONG_PRIVATE_KEY /
//! MALFORMED_ENCRYPTED_DATA / DECRYPTION_FAILED). The fixed key is valid and
//! non-empty, so MISSING_PRIVATE_KEY cannot fire; the round-trip lane must be
//! identity. (In v2.4.1 the crypto layer maps ephemeral-point-parse failures to
//! DECRYPTION_FAILED — the MALFORMED_ENCRYPTED_DATA remap lives in the CLI's
//! decryptKeyValue, doc 03 §4 item 6 — so this target legitimately sees only WRONG
//! and DECRYPTION_FAILED; asserting the full four-set is a superset guard that
//! stays correct if the mapping ever tightens.)

use envrypt::crypto::{self, CryptoError, CryptoErrorCode, SecretKey};
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

/// Fixed test private key: 0x01 repeated — a valid, nonzero, in-range secp256k1
/// scalar. Public key derived once. Deterministic; never `keypair()`/random.
const PRIV_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";

static KEY: LazyLock<(SecretKey, String)> = LazyLock::new(|| {
    let secret = crypto::parse_private_key(PRIV_HEX).expect("fixed test private key is valid");
    let public = crypto::derive(PRIV_HEX).expect("fixed test private key derives");
    (secret, public)
});

/// Assert a decrypt failure maps to exactly one of the four doc 03 §4 conditions.
#[track_caller]
fn assert_one_of_four(err: &CryptoError) {
    match err.code {
        Some(
            CryptoErrorCode::InvalidPrivateKey
            | CryptoErrorCode::WrongPrivateKey
            | CryptoErrorCode::MalformedEncryptedData
            | CryptoErrorCode::DecryptionFailed,
        ) => {}
        other => panic!(
            "crypto decrypt failure mapped outside the four doc 03 §4 conditions: \
             code={other:?} message={:?}",
            err.message
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    let (secret, public) = &*KEY;

    // Lane (a): raw post-base64 wire payload → ecies_decrypt directly.
    if let Err(e) = crypto::fuzz_decrypt_wire_payload(secret, data) {
        assert_one_of_four(&e);
    }

    // Lane (b): full string through the public decrypt entry, unprefixed…
    let s = String::from_utf8_lossy(data);
    if let Err(e) = crypto::decrypt(PRIV_HEX, &s, true) {
        assert_one_of_four(&e);
    }
    // …and with the prefix forced on so the base64/crypto branch always runs.
    let prefixed = format!("{}{}", crypto::ENCRYPTED_PREFIX, s);
    if let Err(e) = crypto::decrypt(PRIV_HEX, &prefixed, true) {
        assert_one_of_four(&e);
    }

    // Lane (c): round-trip identity for arbitrary plaintext.
    let ciphertext = crypto::encrypt(public, &s, true).expect("encrypt with the fixed public key");
    let recovered = crypto::decrypt(PRIV_HEX, &ciphertext, true).expect("decrypt of a fresh ciphertext");
    assert_eq!(
        recovered.as_str(),
        &s[..],
        "ECIES round-trip must be the identity for arbitrary plaintext"
    );
});
