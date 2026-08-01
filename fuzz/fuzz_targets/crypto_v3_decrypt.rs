#![no_main]
//! FUZZ target `crypto_v3_decrypt` — the v3 native encrypted-value format
//! (`crates/envrypt/src/crypto_v3.rs`, spec `docs/envrypt/crypto-v3.md`).
//!
//! The v3 reader is the untrusted-input boundary a `.env` file controls: an
//! `encrypted:<base64url(payload)>` (recipient / X25519) or
//! `locked:<pub>:<base64url(payload)>` (passphrase / Argon2id) value is parsed
//! byte-for-byte — base64url decode, header validation, the authenticated
//! Argon2id param cap (MAX_T_COST/MAX_M_COST), constant-time commitment
//! compare, and the XChaCha20-Poly1305 open — all before any secret is trusted.
//! The `ecies_decrypt` sibling covers the frozen v1 SEC1 path; this drives v3.
//!
//! All lanes run against a FIXED, deterministic X25519 keypair (never random):
//! the private key is a constant and its public key is derived once via the
//! `--cfg fuzzing` `fuzz_public_key_hex` seam, so a crash artifact replays
//! identically in a fresh process.
//!
//! Finding = panic / abort / overflow / OOM / hang. Every malformed value must
//! fail closed with the opaque `V3Error` / `CryptoError` / `None`; a graceful
//! error is a NON-finding. The one asserted property is the recipient
//! round-trip identity `decrypt_v3(encrypt_v3(pt)) == pt`.
//!
//! Lanes over one raw byte buffer (decoded lossily to a UTF-8 `String`):
//! (a) `decrypt_v3` — as-is and with an `encrypted:` prefix forced on so the
//!     base64url + header + AEAD branch is always taken;
//! (b) `unlock_v3` — as-is and framed as `locked:<pub>:<payload>` so the
//!     passphrase branch is always taken;
//! (c) `decrypt_entry` / `unlock_entry` — the version-routing entry points that
//!     dispatch v3 vs the legacy v1 readers on the payload version byte;
//! (d) recipient round-trip identity for arbitrary (valid-UTF-8) plaintext.

use envrypt::crypto_v3;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

/// Fixed X25519 recipient private key (0x01 repeated): any 32 bytes is a valid
/// clamped X25519 scalar. Deterministic; never `keypair_v3()`/random.
const PRIV_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";

/// The matching public key, derived once from `PRIV_HEX` via the fuzzing seam.
static PUB_HEX: LazyLock<String> =
    LazyLock::new(|| crypto_v3::fuzz_public_key_hex(PRIV_HEX).expect("fixed v3 private key derives"));

/// The variable name the value is sealed for (v3 binds the name into the AAD).
const VAR_NAME: &str = "ENVRYPT_SECRET";

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);

    // Lane (a): recipient decrypt over arbitrary strings — never panics; every
    // failure is the opaque V3Error.
    let _ = crypto_v3::decrypt_v3(PRIV_HEX, &s, VAR_NAME);
    let _ = crypto_v3::decrypt_v3(PRIV_HEX, &format!("encrypted:{s}"), VAR_NAME);

    // Lane (b): passphrase unlock over arbitrary strings, as-is and framed so the
    // base64url + Argon2id header branch is always reached (the param cap keeps a
    // tampered header from driving an unbounded KDF/allocation before rejection).
    let _ = crypto_v3::unlock_v3(&s, "passphrase", VAR_NAME);
    let _ = crypto_v3::unlock_v3(&format!("locked:{}:{s}", &*PUB_HEX), "passphrase", VAR_NAME);

    // Lane (c): the version-routing entry points (v3 vs legacy v1 dispatch).
    let _ = crypto_v3::decrypt_entry(PRIV_HEX, &s, VAR_NAME);
    let _ = crypto_v3::unlock_entry(&s, "passphrase", VAR_NAME);

    // Lane (d): recipient round-trip identity for arbitrary plaintext.
    let ciphertext =
        crypto_v3::encrypt_v3(&PUB_HEX, &s, VAR_NAME).expect("encrypt_v3 with the fixed public key");
    let recovered =
        crypto_v3::decrypt_v3(PRIV_HEX, &ciphertext, VAR_NAME).expect("decrypt of a fresh v3 value");
    assert_eq!(
        recovered, s,
        "v3 recipient round-trip must be the identity for arbitrary plaintext"
    );
});
