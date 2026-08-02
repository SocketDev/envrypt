//! The v1 `encrypted:` ECIES read/write core.
//!
//! Normative spec: `docs/envrypt/crypto-formats.md` §1 (byte-exact).
//!
//! Wire format:
//!
//! ```text
//! value   = "encrypted:" + base64(payload)
//! payload = ephemeral_public_key (65 B, uncompressed secp256k1, 0x04-prefixed)
//!        || nonce                (16 B, random, AES-GCM IV)
//!        || gcm_tag              (16 B)   <- tag comes BEFORE ciphertext
//!        || ciphertext           (len(plaintext) B, AES-256-GCM)
//! ```
//!
//! Construction: ECDH on secp256k1 with a fresh ephemeral keypair per encryption
//! (public-key encryption that derives a new shared key for every value). The
//! symmetric key = HKDF-SHA256(ikm = eph_pub_uncompressed(65 B) ||
//! ecdh_point_uncompressed(65 B), no salt, no info, 32 B); AES-256-GCM with a
//! random 16-byte nonce (a number used once per encryption) and a 16-byte tag.
//! Identity public keys are compressed 66-hex; private keys are 64-hex. Encryption
//! is randomized, so two encryptions of one value differ: compare a decrypt
//! round-trip, never the ciphertext bytes.
//!
//! Error mapping is layered. Key-parse failure → `INVALID_PRIVATE_KEY`; GCM tag
//! mismatch → `WRONG_PRIVATE_KEY`; every other failure, including a `bad point:`
//! ephemeral-point-parse error or a symmetric-layer error, → `DECRYPTION_FAILED`
//! with the underlying message embedded verbatim. [`decrypt_key_value`] re-maps a
//! `bad point:`-prefixed failure to `MALFORMED_ENCRYPTED_DATA`. The frozen error
//! strings are pinned by this file's tests and `tests/interop_corpus.rs`.

use std::fmt;

use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aes::Aes256;
use aes_gcm::AesGcm;
use hkdf::Hkdf;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

// Re-exported so a caller can hoist the parse out of a loop. `SecretKey` is what
// [`parse_private_key`] returns and what [`decrypt_with_key`] takes; `PublicKey`
// is what [`parse_public_key`] returns and what [`encrypt_with_key`] takes. Both
// skip the per-value hex-decode and point-parse when many values share one key.
// The keyring itself stores hex, not parsed keys (`keyring::Ring` is
// `IndexMap<String, String>`).
pub use k256::{PublicKey, SecretKey};

/// The value prefix that marks an ECIES-encrypted string.
pub const ENCRYPTED_PREFIX: &str = "encrypted:";

const EPHEMERAL_PUBLIC_KEY_LEN: usize = 65;
const COMPRESSED_PUBLIC_KEY_LEN: usize = 33;
const NONCE_LEN: usize = 16;
const TAG_LEN: usize = 16;

/// secp256k1 field prime p, big-endian. The compressed-point parse distinguishes
/// x ≥ p (`wrong x`) from an in-range x whose x³+7 has no square root
/// (`sqrt error`); see [`parse_sec1_point`].
const FIELD_MODULUS_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

/// AES-256-GCM with a 16-byte nonce (the ECIES nonce length).
type Aes256Gcm16 = AesGcm<Aes256, U16>;

/// Error codes the crypto layer can raise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoErrorCode {
    MissingPrivateKey,
    InvalidPrivateKey,
    WrongPrivateKey,
    MalformedEncryptedData,
    DecryptionFailed,
}

impl CryptoErrorCode {
    /// The stable machine-readable code string (callers may match on it).
    pub fn as_str(self) -> &'static str {
        match self {
            CryptoErrorCode::MissingPrivateKey => "MISSING_PRIVATE_KEY",
            CryptoErrorCode::InvalidPrivateKey => "INVALID_PRIVATE_KEY",
            CryptoErrorCode::WrongPrivateKey => "WRONG_PRIVATE_KEY",
            CryptoErrorCode::MalformedEncryptedData => "MALFORMED_ENCRYPTED_DATA",
            CryptoErrorCode::DecryptionFailed => "DECRYPTION_FAILED",
        }
    }

    /// The issue URL shown in this code's `fix:` help line.
    pub fn issue_url(self) -> &'static str {
        match self {
            CryptoErrorCode::MissingPrivateKey => "https://github.com/SocketDev/envrypt/issues/464",
            CryptoErrorCode::InvalidPrivateKey => "https://github.com/SocketDev/envrypt/issues/465",
            CryptoErrorCode::WrongPrivateKey => "https://github.com/SocketDev/envrypt/issues/466",
            CryptoErrorCode::MalformedEncryptedData => {
                "https://github.com/SocketDev/envrypt/issues/467"
            }
            CryptoErrorCode::DecryptionFailed => "https://github.com/SocketDev/envrypt/issues/757",
        }
    }
}

/// A crypto-layer error: a `code`, a `message`, and an optional `help` line of
/// the form `fix: [<issue url>]`. A `code` of `None` marks a raw error with no
/// code prefix (for example, `derive` on a bad scalar yields a bare
/// `Invalid private key`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoError {
    pub code: Option<CryptoErrorCode>,
    pub message: String,
    pub help: Option<String>,
}

impl CryptoError {
    fn coded(code: CryptoErrorCode, body: &str) -> Self {
        CryptoError {
            code: Some(code),
            message: format!("[{}] {}", code.as_str(), body),
            help: Some(format!("fix: [{}]", code.issue_url())),
        }
    }

    fn raw(message: &str) -> Self {
        CryptoError {
            code: None,
            message: message.to_string(),
            help: None,
        }
    }

    /// The message and help joined as `"<message>. <help>"`.
    pub fn message_with_help(&self) -> String {
        match &self.help {
            Some(help) => format!("{}. {}", self.message, help),
            None => self.message.clone(),
        }
    }

    /// The message with a leading `[CODE] ` prefix stripped (the prefix matches
    /// the regex `^\[[A-Z_]+\] `).
    pub fn primitive_message(&self) -> &str {
        let msg = self.message.as_str();
        if let Some(rest) = msg.strip_prefix('[') {
            if let Some(end) = rest.find("] ") {
                let code = &rest[..end];
                if !code.is_empty() && code.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') {
                    return &rest[end + 2..];
                }
            }
        }
        msg
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CryptoError {}

/// A freshly generated identity keypair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keypair {
    /// Compressed secp256k1 point, 66 hex chars.
    pub public_key: String,
    /// Raw scalar, 64 hex chars.
    pub private_key: String,
}

/// True for any string starting with `encrypted:`. The base64 payload is not
/// validated here.
pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(ENCRYPTED_PREFIX)
}

/// A fresh random keypair: a compressed 66-hex public key and a 64-hex private
/// key.
pub fn keypair() -> Keypair {
    let secret = SecretKey::random(&mut OsRng);
    Keypair {
        public_key: public_key_hex(&secret),
        private_key: hex_encode(&secret.to_bytes()),
    }
}

/// Derives the compressed 66-hex public key from a private key hex. Returns the
/// raw (uncoded) `Invalid private key` error on a bad scalar.
pub fn derive(private_key_hex: &str) -> Result<String, CryptoError> {
    let secret = parse_secret_scalar(private_key_hex)
        .ok_or_else(|| CryptoError::raw("Invalid private key"))?;
    Ok(public_key_hex(&secret))
}

/// Parses a 64-hex private key into a reusable [`SecretKey`], mapping failure to
/// `INVALID_PRIVATE_KEY`. Hex decoding is lenient: it stops at the first non-hex
/// pair and drops a trailing odd nibble, then validity is decided by the 32-byte
/// length and the scalar range check.
pub fn parse_private_key(private_key_hex: &str) -> Result<SecretKey, CryptoError> {
    parse_secret_scalar(private_key_hex).ok_or_else(|| {
        CryptoError::coded(
            CryptoErrorCode::InvalidPrivateKey,
            "could not decrypt using private key",
        )
    })
}

/// The derived compressed public key (66-hex) for an already-parsed secret key.
/// One EC base-point multiplication; the keyring calls it once per private key
/// while building the ring.
pub fn public_key_hex(secret: &SecretKey) -> String {
    hex_encode(secret.public_key().to_encoded_point(true).as_bytes())
}

/// Encrypts `value` for a recipient public key, returning `encrypted:<base64>`.
/// `prefix = false` returns bare base64 without the `encrypted:` marker. Accepts a
/// 66-hex compressed or 130-hex uncompressed public key.
///
/// This writes the v1 layout (`docs/envrypt/crypto-formats.md` §1), kept for
/// compatibility tooling; new values use the v3 format
/// ([`crate::crypto_v3::encrypt_v3`]).
pub fn encrypt(public_key_hex: &str, value: &str, prefix: bool) -> Result<String, CryptoError> {
    let recipient = parse_public_key(public_key_hex)?;
    Ok(encrypt_with_key(&recipient, value, prefix))
}

/// Encrypts `value` against an already-parsed recipient public key, producing the
/// v1 `encrypted:` ECIES layout (`docs/envrypt/crypto-formats.md` §1). A caller
/// encrypting many values against one recipient parses the key once via
/// [`parse_public_key`] and loops on this, skipping the per-value hex-decode and
/// point-parse. Infallible. Tests and the interop vector generator use it to mint
/// fresh v1 values; new production values use the v3 format
/// ([`crate::crypto_v3::encrypt_v3`]).
pub fn encrypt_with_key(recipient: &PublicKey, value: &str, prefix: bool) -> String {
    let payload = ecies_encrypt(recipient, value.as_bytes());
    let encoded = base64_encode(&payload);
    if prefix {
        format!("{ENCRYPTED_PREFIX}{encoded}")
    } else {
        encoded
    }
}

/// Decrypts an `encrypted:` value with a private key hex.
///
/// Control flow: with `prefix = false` the value is treated as bare base64; a
/// value that does not start with `encrypted:` passes through unchanged; an empty
/// private key yields `MISSING_PRIVATE_KEY`; then key-parse, point-parse, and GCM
/// failures map to their codes (`docs/envrypt/crypto-formats.md` §1).
pub fn decrypt(
    private_key_hex: &str,
    encrypted_value: &str,
    prefix: bool,
) -> Result<String, CryptoError> {
    // Pass-through happens BEFORE any key check.
    let Some(base64_payload) = ciphertext_portion(encrypted_value, prefix) else {
        return Ok(encrypted_value.to_string());
    };
    // Empty private key.
    if private_key_hex.is_empty() {
        return Err(CryptoError::coded(
            CryptoErrorCode::MissingPrivateKey,
            "could not decrypt because private key is missing",
        ));
    }
    // The secret key is parsed/validated before touching the payload, so
    // INVALID_PRIVATE_KEY takes precedence over payload errors.
    let secret = parse_private_key(private_key_hex)?;
    decrypt_payload(&secret, base64_payload)
}

/// Decrypts against an already-parsed key. The keyring parses the key once and
/// loops on this; the `encrypted:` prefix check runs before any base64 or crypto
/// work. Same result as [`decrypt`] once the key is known good.
pub fn decrypt_with_key(
    secret: &SecretKey,
    encrypted_value: &str,
    prefix: bool,
) -> Result<String, CryptoError> {
    let Some(base64_payload) = ciphertext_portion(encrypted_value, prefix) else {
        return Ok(encrypted_value.to_string());
    };
    decrypt_payload(secret, base64_payload)
}

/// Decrypts one keyed value, trying each comma-separated private key in order.
///
/// A non-`encrypted:` value passes through; an empty private key yields the keyed
/// `MISSING_PRIVATE_KEY`; otherwise the first key that succeeds wins, and if every
/// key fails the LAST failure is re-mapped to a keyed error naming `key` and
/// `private_key_name`.
pub fn decrypt_key_value(
    key: &str,
    value: &str,
    private_key_name: &str,
    private_key: Option<&str>,
) -> Result<String, CryptoError> {
    if !value.starts_with(ENCRYPTED_PREFIX) {
        return Ok(value.to_string());
    }

    // A missing private key becomes empty.
    let private_key = private_key.unwrap_or("");
    if private_key.is_empty() {
        return Err(keyed_error(
            CryptoErrorCode::MissingPrivateKey,
            key,
            private_key_name,
            private_key,
        ));
    }

    // Try each comma-separated key; a success returns immediately, and the LAST
    // failure is reported with the FULL original comma-joined string in the
    // truncated display.
    let mut decryption_error = None;
    for priv_key in private_key.split(',') {
        match decrypt(priv_key, value, true) {
            Ok(decrypted) => return Ok(decrypted),
            Err(e) => {
                decryption_error = Some(match e.code {
                    Some(CryptoErrorCode::InvalidPrivateKey) => keyed_error(
                        CryptoErrorCode::InvalidPrivateKey,
                        key,
                        private_key_name,
                        private_key,
                    ),
                    Some(CryptoErrorCode::WrongPrivateKey) => keyed_error(
                        CryptoErrorCode::WrongPrivateKey,
                        key,
                        private_key_name,
                        private_key,
                    ),
                    // A malformed ephemeral point arrives as a `bad point:`
                    // message rather than this code, so the message-prefix arm
                    // below is the live path; this code arm stays for the same
                    // mapping.
                    Some(CryptoErrorCode::MalformedEncryptedData) => CryptoError::coded(
                        CryptoErrorCode::MalformedEncryptedData,
                        &format!(
                            "could not decrypt {key} because encrypted data appears malformed"
                        ),
                    ),
                    _ if e.primitive_message().starts_with("bad point:") => CryptoError::coded(
                        CryptoErrorCode::MalformedEncryptedData,
                        &format!(
                            "could not decrypt {key} because encrypted data appears malformed"
                        ),
                    ),
                    _ => {
                        CryptoError::coded(CryptoErrorCode::DecryptionFailed, e.primitive_message())
                    }
                });
            }
        }
    }

    Err(decryption_error.expect("split(',') yields at least one element"))
}

/// `Errors({ key, privateKeyName, privateKey }).missingPrivateKey()` /
/// `.invalidPrivateKey()` / `.wrongPrivateKey()` message shape
/// (`src/lib/helpers/errors.js:124-134, 258-268, 306-316`).
fn keyed_error(
    code: CryptoErrorCode,
    key: &str,
    private_key_name: &str,
    private_key: &str,
) -> CryptoError {
    CryptoError::coded(
        code,
        &format!(
            "could not decrypt {key} using private key '{private_key_name}={}'",
            crate::output::truncate::truncate(Some(private_key))
        ),
    )
}

/// Fuzz entry: decrypts a RAW post-base64 wire payload
/// (`eph_pub(65) || nonce(16) || tag(16) || ct`) against an already-parsed key,
/// bypassing base64 decoding so the fuzzer drives [`ecies_decrypt`] directly over
/// arbitrary bytes. Compiled only under cargo-fuzz's `--cfg fuzzing`; production
/// never sees this symbol. Every returned error is coded, so the caller can assert
/// the code is one of the four crypto conditions.
#[cfg(fuzzing)]
pub fn fuzz_decrypt_wire_payload(
    secret: &SecretKey,
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    ecies_decrypt(secret, payload)
}

// --- internals -------------------------------------------------------------

/// The base64 portion of an encrypted value. With `prefix = false` the whole
/// input is the payload; with `prefix = true` a value not starting with
/// `encrypted:` means pass-through (`None`).
fn ciphertext_portion(encrypted_value: &str, prefix: bool) -> Option<&str> {
    if !prefix {
        return Some(encrypted_value);
    }
    encrypted_value.strip_prefix(ENCRYPTED_PREFIX)
}

/// Node-lenient hex → 32-byte scalar → range-checked secret key.
fn parse_secret_scalar(private_key_hex: &str) -> Option<SecretKey> {
    let bytes = node_hex_decode(private_key_hex);
    if bytes.len() != 32 {
        return None;
    }
    SecretKey::from_slice(&bytes).ok()
}

/// Strict public-key hex parse for `encrypt`, returning a raw (uncoded)
/// `CryptoError` on failure. Public so the write side parses a recipient once per
/// file and loops on [`encrypt_with_key`].
pub fn parse_public_key(public_key_hex: &str) -> Result<PublicKey, CryptoError> {
    let bytes = strict_hex_decode(public_key_hex).ok_or_else(|| {
        CryptoError::raw("Input string must contain hex characters in even length")
    })?;
    parse_sec1_point(&bytes).map_err(|message| CryptoError::raw(&message))
}

/// Parses a SEC1 public-key byte slice, reproducing the frozen error string for
/// each failure (`docs/envrypt/crypto-formats.md` §1; checked on Node v26,
/// 2026-07-11):
///
/// - length neither 33 nor 65 → `second arg must be public key`;
/// - head byte does not match the length (33 ⇒ 0x02/0x03, 65 ⇒ 0x04) →
///   `bad point: got length {len}, expected compressed=33 or uncompressed=65`;
/// - compressed with x ≥ p → `bad point: is not on curve, wrong x`;
/// - compressed with x < p but x³+7 a quadratic non-residue →
///   `bad point: is not on curve, sqrt error: Cannot find square root`;
/// - uncompressed with out-of-range or off-curve coordinates →
///   `bad point: is not on curve`.
///
/// k256's `from_sec1_bytes` accepts exactly the on-curve canonical point set, so
/// only the failure MESSAGES need the extra head/range classification here.
fn parse_sec1_point(bytes: &[u8]) -> Result<PublicKey, String> {
    let len = bytes.len();
    if len != COMPRESSED_PUBLIC_KEY_LEN && len != EPHEMERAL_PUBLIC_KEY_LEN {
        return Err("second arg must be public key".to_string());
    }
    let head_ok = if len == COMPRESSED_PUBLIC_KEY_LEN {
        bytes[0] == 0x02 || bytes[0] == 0x03
    } else {
        bytes[0] == 0x04
    };
    if !head_ok {
        return Err(format!(
            "bad point: got length {len}, expected compressed=33 or uncompressed=65"
        ));
    }
    PublicKey::from_sec1_bytes(bytes).map_err(|_| {
        if len == COMPRESSED_PUBLIC_KEY_LEN {
            if bytes[1..] >= FIELD_MODULUS_BE[..] {
                "bad point: is not on curve, wrong x".to_string()
            } else {
                "bad point: is not on curve, sqrt error: Cannot find square root".to_string()
            }
        } else {
            "bad point: is not on curve".to_string()
        }
    })
}

/// Strict hex decode: even length, hex digits only.
fn strict_hex_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let hi = hex_val(pair[0])?;
            let lo = hex_val(pair[1])?;
            Some(hi << 4 | lo)
        })
        .collect()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    out
}

/// ECIES encrypt: fresh ephemeral keypair, ECDH, HKDF-SHA256, AES-256-GCM with a
/// 16-byte nonce; payload = `eph_pub(65) || nonce(16) || tag(16) || ct`.
fn ecies_encrypt(recipient: &PublicKey, plaintext: &[u8]) -> Vec<u8> {
    let ephemeral = SecretKey::random(&mut OsRng);
    let ephemeral_pub = ephemeral.public_key().to_encoded_point(false);
    let shared = shared_point_uncompressed(&ephemeral, recipient);
    let key = derive_symmetric_key(ephemeral_pub.as_bytes(), &shared);

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let cipher = Aes256Gcm16::new(&key.into());
    let ct_and_tag = cipher
        .encrypt(&nonce.into(), plaintext)
        .expect("AES-GCM encryption of an in-memory buffer cannot fail");
    let (ciphertext, tag) = ct_and_tag.split_at(ct_and_tag.len() - TAG_LEN);

    // Wire layout puts the tag BEFORE the ciphertext.
    let mut payload =
        Vec::with_capacity(EPHEMERAL_PUBLIC_KEY_LEN + NONCE_LEN + TAG_LEN + ciphertext.len());
    payload.extend_from_slice(ephemeral_pub.as_bytes());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(tag);
    payload.extend_from_slice(ciphertext);
    payload
}

/// Base64-decode + ECIES-decrypt + UTF-8 (lossy, like Node's `toString("utf8")`).
fn decrypt_payload(secret: &SecretKey, base64_payload: &str) -> Result<String, CryptoError> {
    let payload = node_base64_decode(base64_payload);
    let plaintext = ecies_decrypt(secret, &payload)?;
    Ok(String::from_utf8_lossy(&plaintext).into_owned())
}

/// ECIES decrypt. Every failure sub-case reproduces the frozen error string
/// (`docs/envrypt/crypto-formats.md` §1; checked on Node v26, 2026-07-11).
fn ecies_decrypt(secret: &SecretKey, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // The point parser accepts BOTH a 33-byte compressed and a 65-byte
    // uncompressed ephemeral key, so a payload of exactly 33 bytes parses as a
    // compressed key (its symmetric portion is then empty and fails below with
    // `Invalid initialization vector`), while every other length below 65 fails
    // the length pre-check with `second arg must be public key`. All point-parse
    // failures surface as DECRYPTION_FAILED with the message embedded;
    // [`decrypt_key_value`] re-maps a `bad point:` prefix to
    // MALFORMED_ENCRYPTED_DATA.
    let key_len = payload.len().min(EPHEMERAL_PUBLIC_KEY_LEN);
    let ephemeral = parse_sec1_point(&payload[..key_len])
        .map_err(|message| CryptoError::coded(CryptoErrorCode::DecryptionFailed, &message))?;

    // Symmetric-layer structural checks (Node error strings, observed table:
    // empty data → invalid IV; short nonce/tag → invalid tag length N where
    // t = len-16 clamped at 0, N = 0 for t == 0 else min(t, 16 - t)).
    let data = &payload[key_len..];
    if data.is_empty() {
        return Err(CryptoError::coded(
            CryptoErrorCode::DecryptionFailed,
            "Invalid initialization vector",
        ));
    }
    if data.len() < NONCE_LEN + TAG_LEN {
        let t = data.len().saturating_sub(NONCE_LEN);
        let n = if t == 0 { 0 } else { t.min(16 - t) };
        return Err(CryptoError::coded(
            CryptoErrorCode::DecryptionFailed,
            &format!("Invalid authentication tag length: {n}"),
        ));
    }

    // ikm uses the UNCOMPRESSED encoding of the parsed point, which equals the
    // wire bytes for the canonical 65-byte form the encryptor emits.
    let shared = shared_point_uncompressed(secret, &ephemeral);
    let ephemeral_uncompressed = ephemeral.to_encoded_point(false);
    let key = derive_symmetric_key(ephemeral_uncompressed.as_bytes(), &shared);

    let nonce: [u8; NONCE_LEN] = data[..NONCE_LEN].try_into().expect("checked length");
    let tag = &data[NONCE_LEN..NONCE_LEN + TAG_LEN];
    let ciphertext = &data[NONCE_LEN + TAG_LEN..];

    // The aead crate expects ct || tag; the wire carries tag || ct, so
    // reassemble before opening.
    let mut ct_and_tag = Vec::with_capacity(ciphertext.len() + TAG_LEN);
    ct_and_tag.extend_from_slice(ciphertext);
    ct_and_tag.extend_from_slice(tag);

    let cipher = Aes256Gcm16::new(&key.into());
    cipher
        .decrypt(&nonce.into(), ct_and_tag.as_slice())
        .map_err(|_| {
            // GCM tag mismatch → WRONG_PRIVATE_KEY.
            CryptoError::coded(
                CryptoErrorCode::WrongPrivateKey,
                "could not decrypt using private key",
            )
        })
}

/// ECDH shared point, serialized UNCOMPRESSED (65 B).
fn shared_point_uncompressed(secret: &SecretKey, public: &PublicKey) -> [u8; 65] {
    let shared = public.to_projective() * *secret.to_nonzero_scalar();
    // secp256k1 has prime order: nonzero scalar × valid point ≠ identity.
    let encoded = shared.to_affine().to_encoded_point(false);
    encoded
        .as_bytes()
        .try_into()
        .expect("uncompressed secp256k1 point is 65 bytes")
}

/// `k = HKDF-SHA256(ikm = eph_pub(65) || shared_point(65), salt = none,
/// info = none, len = 32)`.
fn derive_symmetric_key(ephemeral_pub: &[u8], shared_point: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(ephemeral_pub.len() + shared_point.len());
    ikm.extend_from_slice(ephemeral_pub);
    ikm.extend_from_slice(shared_point);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(&[], &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// Node `Buffer.from(str, "hex")` semantics: case-insensitive byte pairs,
/// decoding stops at the first invalid pair, a trailing odd nibble is dropped.
fn node_hex_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let (pairs, _) = bytes.as_chunks::<2>();
    for pair in pairs {
        match (hex_val(pair[0]), hex_val(pair[1])) {
            (Some(hi), Some(lo)) => out.push(hi << 4 | lo),
            _ => return out,
        }
    }
    out
}

/// Node `Buffer.from(str, "base64")` semantics (probed on Node v26): both the
/// standard and url alphabets are accepted, other characters (incl. whitespace)
/// are skipped, the first `=` terminates decoding, and a trailing partial group
/// of 2/3 characters decodes to 1/2 bytes (a lone character is dropped).
fn node_base64_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3 + 2);
    let mut acc: u32 = 0;
    let mut nsextets = 0u8;
    for b in s.bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => continue, // skip invalid characters
        };
        acc = acc << 6 | u32::from(val);
        nsextets += 1;
        if nsextets == 4 {
            out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]);
            acc = 0;
            nsextets = 0;
        }
    }
    match nsextets {
        2 => out.push((acc >> 4) as u8),
        3 => out.extend_from_slice(&[(acc >> 10) as u8, (acc >> 2) as u8]),
        _ => {} // 0 sextets: nothing pending; 1 sextet: dropped, like Node
    }
    out
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding — `Buffer.prototype.toString("base64")`.
fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let (chunks, rem) = bytes.as_chunks::<3>();
    for chunk in chunks {
        let acc = u32::from(chunk[0]) << 16 | u32::from(chunk[1]) << 8 | u32::from(chunk[2]);
        for shift in [18, 12, 6, 0] {
            out.push(BASE64_ALPHABET[(acc >> shift & 0x3f) as usize] as char);
        }
    }
    match *rem {
        [a] => {
            let acc = u32::from(a) << 16;
            out.push(BASE64_ALPHABET[(acc >> 18 & 0x3f) as usize] as char);
            out.push(BASE64_ALPHABET[(acc >> 12 & 0x3f) as usize] as char);
            out.push_str("==");
        }
        [a, b] => {
            let acc = u32::from(a) << 16 | u32::from(b) << 8;
            out.push(BASE64_ALPHABET[(acc >> 18 & 0x3f) as usize] as char);
            out.push(BASE64_ALPHABET[(acc >> 12 & 0x3f) as usize] as char);
            out.push(BASE64_ALPHABET[(acc >> 6 & 0x3f) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests;
