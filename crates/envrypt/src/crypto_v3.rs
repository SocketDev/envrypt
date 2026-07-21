//! The v3 native encrypted-value format — the format envrypt **writes**.
//!
//! Normative spec: `docs/envrypt/crypto-v3.md` (byte-exact). The v1 layouts in
//! `docs/envrypt/crypto-formats.md` §1–§2 stay readable through [`crate::crypto`]
//! and [`crate::services::lock`]; this module owns everything version `0x03`.
//!
//! Two modes share one header/AAD/commitment discipline:
//!
//! - **Recipient** (`encrypted:<base64url(payload)>`): X25519 ECDH with a fresh
//!   ephemeral keypair per value, key = HKDF-SHA256(ikm = shared, salt = ∅,
//!   info = `"envrypt:v3:recip"` || eph_pub, 32 B), XChaCha20-Poly1305 with a
//!   fresh 24-byte random nonce.
//! - **Passphrase** (`locked:<public_key_hex>:<base64url(payload)>`): key =
//!   Argon2id(passphrase, 16-byte salt, t/m/p from the header, 32 B), same AEAD.
//!
//! The header bytes double as the AAD prefix: `AAD = header || 0x00 ||
//! variable_name_utf8`. Binding the variable name means a value only opens under
//! the name it was sealed for (relocation resistance). A 32-byte key commitment
//! (`HKDF-SHA256(ikm = key, salt = ∅, info = "envrypt:v3:commit", 32 B)`) is
//! stored in the payload and verified in constant time **before** any AEAD work,
//! making the cipher committing (resistant to partitioning attacks).
//!
//! Every v3 failure collapses to the one opaque [`V3Error`] — wrong key, wrong
//! passphrase, wrong name, and malformed bytes are indistinguishable to a caller.
//!
//! Robustness guard: Argon2id header params are capped at [`MAX_T_COST`] /
//! [`MAX_M_COST`] on both the write and the read path. The params can only be
//! authenticated *after* the KDF has run, so the cap keeps a tampered header
//! from demanding an astronomically expensive derivation (or a multi-gigabyte
//! allocation) before verification can reject it.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};

use crate::crypto::{CryptoError, CryptoErrorCode, ENCRYPTED_PREFIX};

/// `locked:` — the string prefix shared by the v1 and v3 passphrase forms.
pub const LOCKED_PREFIX: &str = "locked:";

/// The v3 version byte (payload offset 0, both modes).
pub const VERSION_V3: u8 = 0x03;

/// Header `mode` byte: recipient (X25519 + HKDF).
const MODE_RECIPIENT: u8 = 0x01;
/// Header `mode` byte: passphrase (Argon2id).
const MODE_PASSPHRASE: u8 = 0x02;
/// Header `aead_id` byte: XChaCha20-Poly1305.
const AEAD_XCHACHA20_POLY1305: u8 = 0x01;
/// Header `kdf_id` byte: none (recipient mode).
const KDF_NONE: u8 = 0x00;
/// Header `kdf_id` byte: Argon2id (passphrase mode).
const KDF_ARGON2ID: u8 = 0x02;

/// Recipient header length: version, mode, aead_id, kdf_id.
const RECIPIENT_HEADER_LEN: usize = 4;
/// Passphrase header length: the recipient fields + t_cost(4 BE) + m_cost(4 BE) + p(1).
const PASSPHRASE_HEADER_LEN: usize = 13;

const X25519_PUBLIC_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const COMMITMENT_LEN: usize = 32;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;

/// HKDF `info` domain-separation prefix for the recipient key schedule.
const INFO_RECIPIENT: &[u8] = b"envrypt:v3:recip";
/// HKDF `info` for the key commitment.
const INFO_COMMIT: &[u8] = b"envrypt:v3:commit";

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// The single opaque v3 error. Every v3 failure — malformed payload, unknown
/// header field, wrong key, wrong passphrase, wrong variable name, commitment or
/// AEAD mismatch, invalid input — collapses to this one value, so the format
/// never reveals *why* an operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3Error;

impl std::fmt::Display for V3Error {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("v3 crypto operation failed")
  }
}

impl std::error::Error for V3Error {}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// A freshly generated X25519 identity keypair for v3 recipient encryption.
/// Both keys are 32 bytes, hex-encoded (64 lowercase hex chars).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3Keypair {
  /// The X25519 public key, 64 lowercase hex chars.
  pub public_key: String,
  /// The X25519 private key (clamped scalar seed), 64 lowercase hex chars.
  pub private_key: String,
}

/// Generate a fresh X25519 keypair (public hex = lowercase hex of the 32-byte
/// public key).
pub fn keypair_v3() -> V3Keypair {
  let secret = StaticSecret::random_from_rng(OsRng);
  let public = X25519Public::from(&secret);
  V3Keypair {
    public_key: hex_encode(public.as_bytes()),
    private_key: hex_encode(&secret.to_bytes()),
  }
}

/// Parse a 64-hex-char X25519 key into its 32 raw bytes.
fn parse_key_hex(key_hex: &str) -> Result<[u8; 32], V3Error> {
  let bytes = hex_decode(key_hex).ok_or(V3Error)?;
  bytes.try_into().map_err(|_| V3Error)
}

/// Fuzz seam: derive the recipient public-key hex from a private-key hex so the
/// `crypto_v3_decrypt` target can build a matched keypair from a FIXED private
/// key (no RNG, deterministic corpus replay) for its round-trip lane. Compiled
/// only under cargo-fuzz's `--cfg fuzzing`; production never sees this symbol.
#[cfg(fuzzing)]
pub fn fuzz_public_key_hex(private_key_hex: &str) -> Option<String> {
  let secret = StaticSecret::from(parse_key_hex(private_key_hex).ok()?);
  Some(hex_encode(X25519Public::from(&secret).as_bytes()))
}

// ---------------------------------------------------------------------------
// Argon2id parameters
// ---------------------------------------------------------------------------

/// Argon2id cost parameters carried in (and authenticated by) the passphrase
/// header. Defaults: `t = 3`, `m = 65536` KiB (64 MiB), `p = 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
  /// Time cost (iterations), header `argon_t_cost` (u32 BE).
  pub t_cost: u32,
  /// Memory cost in KiB, header `argon_m_cost` (u32 BE).
  pub m_cost: u32,
  /// Lanes (parallelism), header `argon_p` (u8).
  pub p: u8,
}

impl Default for Argon2Params {
  fn default() -> Self {
    Argon2Params {
      t_cost: 3,
      m_cost: 65536,
      p: 1,
    }
  }
}

/// Work-factor ceiling: the largest `t_cost` accepted on both the write and the
/// read path. The header's KDF params are authenticated only *after* the KDF has
/// run, so without a ceiling a tampered header could demand an astronomically
/// expensive derivation before verification can fail (a denial-of-service on the
/// decryptor). 2^12 iterations is orders of magnitude above the default (3) and
/// any practical hardening choice.
pub const MAX_T_COST: u32 = 1 << 12;

/// Work-factor ceiling: the largest `m_cost` (KiB) accepted on both the write
/// and the read path — 2^20 KiB = 1 GiB. Same rationale as [`MAX_T_COST`]: a
/// tampered header must never drive a multi-gigabyte allocation before the
/// commitment/tag check can reject it.
pub const MAX_M_COST: u32 = 1 << 20;

/// Derive the 32-byte Argon2id key for `passphrase`/`salt` under `params`.
fn argon2id_key(passphrase: &str, salt: &[u8], params: &Argon2Params) -> Result<[u8; 32], V3Error> {
  if params.t_cost > MAX_T_COST || params.m_cost > MAX_M_COST {
    return Err(V3Error);
  }
  let algo_params = argon2::Params::new(
    params.m_cost,
    params.t_cost,
    u32::from(params.p),
    Some(KEY_LEN),
  )
  .map_err(|_| V3Error)?;
  let argon = argon2::Argon2::new(
    argon2::Algorithm::Argon2id,
    argon2::Version::V0x13,
    algo_params,
  );
  let mut key = [0u8; KEY_LEN];
  argon
    .hash_password_into(passphrase.as_bytes(), salt, &mut key)
    .map_err(|_| V3Error)?;
  Ok(key)
}

// ---------------------------------------------------------------------------
// Header + AAD + commitment
// ---------------------------------------------------------------------------

/// The 4-byte recipient header: version, mode, aead_id, kdf_id = none.
fn recipient_header() -> [u8; RECIPIENT_HEADER_LEN] {
  [
    VERSION_V3,
    MODE_RECIPIENT,
    AEAD_XCHACHA20_POLY1305,
    KDF_NONE,
  ]
}

/// The 13-byte passphrase header: the four id bytes plus the Argon2id params
/// (t_cost u32 BE, m_cost u32 BE, p u8).
fn passphrase_header(params: &Argon2Params) -> [u8; PASSPHRASE_HEADER_LEN] {
  let mut header = [0u8; PASSPHRASE_HEADER_LEN];
  header[0] = VERSION_V3;
  header[1] = MODE_PASSPHRASE;
  header[2] = AEAD_XCHACHA20_POLY1305;
  header[3] = KDF_ARGON2ID;
  header[4..8].copy_from_slice(&params.t_cost.to_be_bytes());
  header[8..12].copy_from_slice(&params.m_cost.to_be_bytes());
  header[12] = params.p;
  header
}

/// `AAD = header || 0x00 || variable_name_utf8`. The `0x00` separator keeps a
/// header/name pair from colliding with any other split of the same bytes.
fn build_aad(header: &[u8], var_name: &str) -> Vec<u8> {
  let mut aad = Vec::with_capacity(header.len() + 1 + var_name.len());
  aad.extend_from_slice(header);
  aad.push(0x00);
  aad.extend_from_slice(var_name.as_bytes());
  aad
}

/// `commitment = HKDF-SHA256(ikm = key, salt = ∅, info = "envrypt:v3:commit", 32 B)`.
fn commitment(key: &[u8; KEY_LEN]) -> [u8; COMMITMENT_LEN] {
  hkdf_sha256(key, INFO_COMMIT)
}

/// Recipient key schedule: `HKDF-SHA256(ikm = shared, salt = ∅,
/// info = "envrypt:v3:recip" || eph_pub, 32 B)`.
fn recipient_key(shared: &[u8; 32], eph_pub: &[u8; X25519_PUBLIC_LEN]) -> [u8; KEY_LEN] {
  let mut info = Vec::with_capacity(INFO_RECIPIENT.len() + X25519_PUBLIC_LEN);
  info.extend_from_slice(INFO_RECIPIENT);
  info.extend_from_slice(eph_pub);
  hkdf_sha256(shared, &info)
}

fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> [u8; 32] {
  let hk = Hkdf::<Sha256>::new(None, ikm);
  let mut okm = [0u8; 32];
  hk.expand(info, &mut okm)
    .expect("32 bytes is a valid HKDF-SHA256 output length");
  okm
}

// ---------------------------------------------------------------------------
// AEAD seal/open (shared by both modes)
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` under `key` with a fresh 24-byte nonce and the v3 AAD,
/// returning `(nonce, commitment, tag, ciphertext)` ready for payload assembly.
fn seal(
  key: &[u8; KEY_LEN],
  header: &[u8],
  var_name: &str,
  plaintext: &[u8],
) -> ([u8; NONCE_LEN], [u8; COMMITMENT_LEN], Vec<u8>, Vec<u8>) {
  let mut nonce = [0u8; NONCE_LEN];
  OsRng.fill_bytes(&mut nonce);

  let aad = build_aad(header, var_name);
  let cipher = XChaCha20Poly1305::new(&(*key).into());
  let mut ct_and_tag = cipher
    .encrypt(
      &nonce.into(),
      Payload {
        msg: plaintext,
        aad: &aad,
      },
    )
    .expect("XChaCha20-Poly1305 encryption of an in-memory buffer cannot fail");
  // The AEAD emits ct || tag; the payload stores the tag BEFORE the ciphertext
  // (the file-format convention shared with the v1 layouts).
  let tag = ct_and_tag.split_off(ct_and_tag.len() - TAG_LEN);
  let ciphertext = ct_and_tag;

  (nonce, commitment(key), tag, ciphertext)
}

/// Decrypt-order steps 3–5 (spec: "Decrypt order"): constant-time commitment
/// check **before** the AEAD, then XChaCha20-Poly1305 open, then strict UTF-8.
fn open(
  key: &[u8; KEY_LEN],
  header: &[u8],
  var_name: &str,
  stored_commitment: &[u8],
  nonce: &[u8],
  tag: &[u8],
  ciphertext: &[u8],
) -> Result<String, V3Error> {
  // Step 3 — recompute the commitment; constant-time compare; mismatch fails
  // before any AEAD work (a wrong key/passphrase stops here).
  let expected = commitment(key);
  if expected.as_slice().ct_eq(stored_commitment).unwrap_u8() != 1 {
    return Err(V3Error);
  }

  // Step 4 — rebuild the AAD and open. The aead crate wants ct || tag; the
  // payload stores tag || ct, so reassemble.
  let aad = build_aad(header, var_name);
  let mut ct_and_tag = Vec::with_capacity(ciphertext.len() + tag.len());
  ct_and_tag.extend_from_slice(ciphertext);
  ct_and_tag.extend_from_slice(tag);
  let cipher = XChaCha20Poly1305::new(&(*key).into());
  let plaintext = cipher
    .decrypt(
      nonce.into(),
      Payload {
        msg: &ct_and_tag,
        aad: &aad,
      },
    )
    .map_err(|_| V3Error)?;

  // Step 5 — strict UTF-8.
  String::from_utf8(plaintext).map_err(|_| V3Error)
}

// ---------------------------------------------------------------------------
// Recipient mode — the v3 `encrypted:` value
// ---------------------------------------------------------------------------

/// Assemble a recipient payload from raw parts (also drives the non-UTF-8
/// coverage path in unit tests, which is why it takes byte plaintext).
fn seal_recipient(
  recipient_public: &[u8; X25519_PUBLIC_LEN],
  plaintext: &[u8],
  var_name: &str,
) -> Vec<u8> {
  let header = recipient_header();

  // Fresh ephemeral X25519 keypair per value.
  let ephemeral = EphemeralSecret::random_from_rng(OsRng);
  let eph_pub = X25519Public::from(&ephemeral);
  let shared = ephemeral.diffie_hellman(&X25519Public::from(*recipient_public));
  let key = recipient_key(shared.as_bytes(), eph_pub.as_bytes());

  let (nonce, commit, tag, ciphertext) = seal(&key, &header, var_name, plaintext);

  // payload = header(4) | eph_pub(32) | nonce(24) | commitment(32) | tag(16) | ct
  let mut payload = Vec::with_capacity(
    RECIPIENT_HEADER_LEN
      + X25519_PUBLIC_LEN
      + NONCE_LEN
      + COMMITMENT_LEN
      + TAG_LEN
      + ciphertext.len(),
  );
  payload.extend_from_slice(&header);
  payload.extend_from_slice(eph_pub.as_bytes());
  payload.extend_from_slice(&nonce);
  payload.extend_from_slice(&commit);
  payload.extend_from_slice(&tag);
  payload.extend_from_slice(&ciphertext);
  payload
}

/// Encrypt `plaintext` for the variable `var_name` to an X25519 recipient,
/// producing the v3 `encrypted:<base64url(payload)>` string form (base64url,
/// no padding). Fails (opaquely) on a malformed recipient key.
pub fn encrypt_v3(
  recipient_public_key_hex: &str,
  plaintext: &str,
  var_name: &str,
) -> Result<String, V3Error> {
  let recipient = parse_key_hex(recipient_public_key_hex)?;
  let payload = seal_recipient(&recipient, plaintext.as_bytes(), var_name);
  Ok(format!("{ENCRYPTED_PREFIX}{}", base64url_encode(&payload)))
}

/// Decrypt a v3 `encrypted:` value sealed for `var_name` with the recipient's
/// X25519 private key. Every failure is the opaque [`V3Error`].
pub fn decrypt_v3(
  private_key_hex: &str,
  encrypted_value: &str,
  var_name: &str,
) -> Result<String, V3Error> {
  let payload_b64 = encrypted_value
    .strip_prefix(ENCRYPTED_PREFIX)
    .ok_or(V3Error)?;
  let payload = base64url_decode(payload_b64).ok_or(V3Error)?;
  open_recipient(private_key_hex, &payload, var_name)
}

/// Decrypt-order steps 1–2 for recipient mode: parse/validate the header,
/// derive the key via ECDH + HKDF, then hand off to [`open`].
fn open_recipient(
  private_key_hex: &str,
  payload: &[u8],
  var_name: &str,
) -> Result<String, V3Error> {
  // Step 1 — read the header; reject unknown version/mode/aead_id/kdf_id.
  let min = RECIPIENT_HEADER_LEN + X25519_PUBLIC_LEN + NONCE_LEN + COMMITMENT_LEN + TAG_LEN;
  if payload.len() < min {
    return Err(V3Error);
  }
  let header = &payload[..RECIPIENT_HEADER_LEN];
  if header != recipient_header().as_slice() {
    return Err(V3Error);
  }

  let mut at = RECIPIENT_HEADER_LEN;
  let eph_pub: [u8; X25519_PUBLIC_LEN] = payload[at..at + X25519_PUBLIC_LEN]
    .try_into()
    .expect("length checked");
  at += X25519_PUBLIC_LEN;
  let nonce = &payload[at..at + NONCE_LEN];
  at += NONCE_LEN;
  let stored_commitment = &payload[at..at + COMMITMENT_LEN];
  at += COMMITMENT_LEN;
  let tag = &payload[at..at + TAG_LEN];
  at += TAG_LEN;
  let ciphertext = &payload[at..];

  // Step 2 — derive the key (ECDH + HKDF bound to this exact handshake).
  let secret = StaticSecret::from(parse_key_hex(private_key_hex)?);
  let shared = secret.diffie_hellman(&X25519Public::from(eph_pub));
  let key = recipient_key(shared.as_bytes(), &eph_pub);

  open(
    &key,
    header,
    var_name,
    stored_commitment,
    nonce,
    tag,
    ciphertext,
  )
}

// ---------------------------------------------------------------------------
// Passphrase mode — the v3 `locked:` value
// ---------------------------------------------------------------------------

/// Assemble a passphrase payload from raw parts (byte plaintext for the same
/// coverage reason as [`seal_recipient`]).
fn seal_passphrase(
  passphrase: &str,
  plaintext: &[u8],
  var_name: &str,
  params: &Argon2Params,
) -> Result<Vec<u8>, V3Error> {
  let header = passphrase_header(params);

  let mut salt = [0u8; SALT_LEN];
  OsRng.fill_bytes(&mut salt);
  let key = argon2id_key(passphrase, &salt, params)?;

  let (nonce, commit, tag, ciphertext) = seal(&key, &header, var_name, plaintext);

  // payload = header(13) | salt(16) | nonce(24) | commitment(32) | tag(16) | ct
  let mut payload = Vec::with_capacity(
    PASSPHRASE_HEADER_LEN + SALT_LEN + NONCE_LEN + COMMITMENT_LEN + TAG_LEN + ciphertext.len(),
  );
  payload.extend_from_slice(&header);
  payload.extend_from_slice(&salt);
  payload.extend_from_slice(&nonce);
  payload.extend_from_slice(&commit);
  payload.extend_from_slice(&tag);
  payload.extend_from_slice(&ciphertext);
  Ok(payload)
}

/// Lock `plaintext` (typically a private key) for the variable `var_name` under
/// a passphrase, producing the v3 `locked:<public_key_hex>:<base64url(payload)>`
/// string form (base64url, no padding). `public_key_hex` is the identity the
/// locked value pairs with, echoed into the string frame exactly like v1.
/// Fails (opaquely) on unusable Argon2 parameters.
pub fn lock_v3(
  public_key_hex: &str,
  plaintext: &str,
  passphrase: &str,
  var_name: &str,
  params: &Argon2Params,
) -> Result<String, V3Error> {
  let payload = seal_passphrase(passphrase, plaintext.as_bytes(), var_name, params)?;
  Ok(format!(
    "{LOCKED_PREFIX}{public_key_hex}:{}",
    base64url_encode(&payload)
  ))
}

/// Unlock a v3 `locked:` value sealed for `var_name` with its passphrase.
/// Every failure is the opaque [`V3Error`].
pub fn unlock_v3(locked_value: &str, passphrase: &str, var_name: &str) -> Result<String, V3Error> {
  let payload = locked_payload(locked_value).ok_or(V3Error)?;
  open_passphrase(passphrase, &payload, var_name)
}

/// Extract the decoded payload of a `locked:<pub>:<base64url>` string
/// (everything after the second `:` is the payload, exactly like v1 parsing).
fn locked_payload(locked_value: &str) -> Option<Vec<u8>> {
  let rest = locked_value.strip_prefix(LOCKED_PREFIX)?;
  let (_public_hex, payload_b64) = rest.split_once(':')?;
  base64url_decode(payload_b64)
}

/// Decrypt-order steps 1–2 for passphrase mode: parse/validate the header
/// (including the authenticated Argon2id params), derive the key, hand off to
/// [`open`].
fn open_passphrase(passphrase: &str, payload: &[u8], var_name: &str) -> Result<String, V3Error> {
  // Step 1 — read the header; reject unknown version/mode/aead_id/kdf_id.
  let min = PASSPHRASE_HEADER_LEN + SALT_LEN + NONCE_LEN + COMMITMENT_LEN + TAG_LEN;
  if payload.len() < min {
    return Err(V3Error);
  }
  let header = &payload[..PASSPHRASE_HEADER_LEN];
  if header[..4]
    != [
      VERSION_V3,
      MODE_PASSPHRASE,
      AEAD_XCHACHA20_POLY1305,
      KDF_ARGON2ID,
    ]
  {
    return Err(V3Error);
  }
  let params = Argon2Params {
    t_cost: u32::from_be_bytes(header[4..8].try_into().expect("length checked")),
    m_cost: u32::from_be_bytes(header[8..12].try_into().expect("length checked")),
    p: header[12],
  };

  let mut at = PASSPHRASE_HEADER_LEN;
  let salt = &payload[at..at + SALT_LEN];
  at += SALT_LEN;
  let nonce = &payload[at..at + NONCE_LEN];
  at += NONCE_LEN;
  let stored_commitment = &payload[at..at + COMMITMENT_LEN];
  at += COMMITMENT_LEN;
  let tag = &payload[at..at + TAG_LEN];
  at += TAG_LEN;
  let ciphertext = &payload[at..];

  // Step 2 — derive the key with the params from the (authenticated) header.
  let key = argon2id_key(passphrase, salt, &params)?;

  open(
    &key,
    header,
    var_name,
    stored_commitment,
    nonce,
    tag,
    ciphertext,
  )
}

// ---------------------------------------------------------------------------
// Version routing (the decrypt pipeline's entry points)
// ---------------------------------------------------------------------------

/// Decrypt one `.env` entry value, routing on the payload version byte:
/// first byte `0x03` → the v3 recipient path (name-bound); anything else →
/// the legacy v1 SEC1 path in [`crate::crypto::decrypt`], which ignores the
/// name. A value without the `encrypted:` prefix passes through unchanged
/// (identical to the v1 pass-through contract).
pub fn decrypt_entry(
  private_key_hex: &str,
  value: &str,
  var_name: &str,
) -> Result<String, CryptoError> {
  let Some(payload_b64) = value.strip_prefix(ENCRYPTED_PREFIX) else {
    return Ok(value.to_string());
  };
  if first_payload_byte(payload_b64) == Some(VERSION_V3) {
    return decrypt_v3(private_key_hex, value, var_name).map_err(opaque_crypto_error);
  }
  crate::crypto::decrypt(private_key_hex, value, true)
}

/// Unlock one `locked:` value, routing on the payload version byte: first byte
/// `0x03` → the v3 passphrase path (name-bound); anything else → the legacy v1
/// path in [`crate::services::lock::unlock_value`], which ignores the name.
pub fn unlock_entry(locked_value: &str, passphrase: &str, var_name: &str) -> Option<String> {
  let payload_b64 = locked_value
    .strip_prefix(LOCKED_PREFIX)
    .and_then(|rest| rest.split_once(':'))
    .map(|(_public, payload)| payload);
  if payload_b64.and_then(first_payload_byte) == Some(VERSION_V3) {
    return unlock_v3(locked_value, passphrase, var_name).ok();
  }
  crate::services::lock::unlock_value(locked_value, passphrase)
}

/// Map the opaque v3 error into the pipeline's error shape without adding any
/// detail (the message stays uniform for every v3 failure).
fn opaque_crypto_error(_: V3Error) -> CryptoError {
  CryptoError {
    code: Some(CryptoErrorCode::DecryptionFailed),
    message: "[DECRYPTION_FAILED] could not decrypt value".to_string(),
    help: None,
  }
}

/// Decode the first payload byte for routing. Tolerant of BOTH base64 alphabets
/// (v1 values use the standard alphabet, v3 uses base64url) — the two agree on
/// every character that can encode a first byte, so routing never misreads a
/// version byte.
fn first_payload_byte(payload_b64: &str) -> Option<u8> {
  let mut sextets = [0u8; 2];
  let mut have = 0;
  for c in payload_b64.bytes() {
    let val = match c {
      b'A'..=b'Z' => c - b'A',
      b'a'..=b'z' => c - b'a' + 26,
      b'0'..=b'9' => c - b'0' + 52,
      b'+' | b'-' => 62,
      b'/' | b'_' => 63,
      _ => return None,
    };
    sextets[have] = val;
    have += 1;
    if have == 2 {
      return Some(sextets[0] << 2 | sextets[1] >> 4);
    }
  }
  None
}

// ---------------------------------------------------------------------------
// base64url (URL-safe alphabet, no padding) + hex
// ---------------------------------------------------------------------------

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode bytes as unpadded URL-safe base64 (the v3 payload encoding, shared
/// with the v1 `locked:` frame).
fn base64url_encode(bytes: &[u8]) -> String {
  let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
  let (chunks, rem) = bytes.as_chunks::<3>();
  for chunk in chunks {
    let acc = u32::from(chunk[0]) << 16 | u32::from(chunk[1]) << 8 | u32::from(chunk[2]);
    for shift in [18, 12, 6, 0] {
      out.push(B64URL[(acc >> shift & 0x3f) as usize] as char);
    }
  }
  match *rem {
    [a] => {
      let acc = u32::from(a) << 16;
      out.push(B64URL[(acc >> 18 & 0x3f) as usize] as char);
      out.push(B64URL[(acc >> 12 & 0x3f) as usize] as char);
    }
    [a, b] => {
      let acc = u32::from(a) << 16 | u32::from(b) << 8;
      out.push(B64URL[(acc >> 18 & 0x3f) as usize] as char);
      out.push(B64URL[(acc >> 12 & 0x3f) as usize] as char);
      out.push(B64URL[(acc >> 6 & 0x3f) as usize] as char);
    }
    _ => {}
  }
  out
}

/// Strict unpadded base64url decode: URL-safe alphabet only, no `=`, no
/// whitespace, and a lone trailing sextet is malformed.
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
  fn val(c: u8) -> Option<u8> {
    match c {
      b'A'..=b'Z' => Some(c - b'A'),
      b'a'..=b'z' => Some(c - b'a' + 26),
      b'0'..=b'9' => Some(c - b'0' + 52),
      b'-' => Some(62),
      b'_' => Some(63),
      _ => None,
    }
  }
  let bytes = s.as_bytes();
  let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
  for chunk in bytes.chunks(4) {
    if chunk.len() == 1 {
      return None;
    }
    let mut acc = 0u32;
    for &c in chunk {
      acc = acc << 6 | u32::from(val(c)?);
    }
    let pad = 4 - chunk.len();
    acc <<= 6 * pad as u32;
    let be = acc.to_be_bytes();
    out.extend_from_slice(&be[1..4 - pad]);
  }
  Some(out)
}

/// Lowercase hex encode.
fn hex_encode(bytes: &[u8]) -> String {
  let mut out = String::with_capacity(bytes.len() * 2);
  for b in bytes {
    out.push(char::from_digit(u32::from(b >> 4), 16).expect("nibble < 16"));
    out.push(char::from_digit(u32::from(b & 0xf), 16).expect("nibble < 16"));
  }
  out
}

/// Strict hex decode: even length, hex digits only (either case).
fn hex_decode(s: &str) -> Option<Vec<u8>> {
  fn val(c: u8) -> Option<u8> {
    match c {
      b'0'..=b'9' => Some(c - b'0'),
      b'a'..=b'f' => Some(c - b'a' + 10),
      b'A'..=b'F' => Some(c - b'A' + 10),
      _ => None,
    }
  }
  let bytes = s.as_bytes();
  if !bytes.len().is_multiple_of(2) {
    return None;
  }
  bytes
    .as_chunks::<2>()
    .0
    .iter()
    .map(|pair| Some(val(pair[0])? << 4 | val(pair[1])?))
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Cheap Argon2id params for loops (the one default-params round trip lives
  /// in `tests/crypto_v3.rs`).
  const FAST: Argon2Params = Argon2Params {
    t_cost: 1,
    m_cost: 8192,
    p: 1,
  };

  // -- encodings ------------------------------------------------------------

  #[test]
  fn base64url_round_trips_every_remainder_length() {
    for len in 0..8usize {
      let bytes: Vec<u8> = (0..len as u8).map(|b| b.wrapping_mul(37) ^ 0xa5).collect();
      let encoded = base64url_encode(&bytes);
      assert!(
        !encoded.contains('=') && !encoded.contains('+') && !encoded.contains('/'),
        "unpadded URL-safe alphabet only: {encoded:?}"
      );
      assert_eq!(base64url_decode(&encoded), Some(bytes), "len {len}");
    }
    // Alphabet positions 62/63 map to '-' and '_'.
    assert_eq!(base64url_encode(&[0xfb, 0xff, 0xfe]), "-__-");
    assert_eq!(base64url_decode("-__-"), Some(vec![0xfb, 0xff, 0xfe]));
  }

  #[test]
  fn base64url_decode_rejects_malformed_input() {
    assert_eq!(base64url_decode("a"), None, "lone trailing sextet");
    assert_eq!(base64url_decode("aGVsbG8="), None, "padding is rejected");
    assert_eq!(base64url_decode("aGV+"), None, "standard-alphabet '+'");
    assert_eq!(base64url_decode("aG Vs"), None, "whitespace");
    assert_eq!(base64url_decode(""), Some(Vec::new()), "empty is empty");
  }

  #[test]
  fn hex_helpers_round_trip_and_reject_malformed() {
    let bytes = [0x00u8, 0x0f, 0xf0, 0xff, 0x5a];
    let hex = hex_encode(&bytes);
    assert_eq!(hex, "000ff0ff5a");
    assert_eq!(hex_decode(&hex), Some(bytes.to_vec()));
    assert_eq!(hex_decode("ABCDEF"), Some(vec![0xab, 0xcd, 0xef]));
    assert_eq!(hex_decode("abc"), None, "odd length");
    assert_eq!(hex_decode("zz"), None, "hex digits only");
    assert_eq!(hex_decode("0g"), None, "second nibble invalid");
    assert_eq!(parse_key_hex(&"ab".repeat(31)), Err(V3Error), "short key");
    assert_eq!(parse_key_hex("not-hex"), Err(V3Error));
  }

  #[test]
  fn first_payload_byte_reads_both_alphabets() {
    // The v3 recipient payload starts 0x03 0x01 → "AwE…" in either alphabet.
    assert_eq!(first_payload_byte("AwE"), Some(0x03));
    // A v1 payload starts with the SEC1 0x04 prefix → "B…".
    assert_eq!(first_payload_byte("BIAy"), Some(0x04));
    // Characters 62/63 from BOTH alphabets decode identically.
    assert_eq!(first_payload_byte("+w"), first_payload_byte("-w"));
    assert_eq!(first_payload_byte("/w"), first_payload_byte("_w"));
    // Digits sit at alphabet positions 52–61.
    assert_eq!(first_payload_byte("0A"), Some(52 << 2));
    // Too short / invalid characters yield no byte.
    assert_eq!(first_payload_byte(""), None);
    assert_eq!(first_payload_byte("A"), None);
    assert_eq!(first_payload_byte("!!"), None);
  }

  // -- headers, AAD, commitment ---------------------------------------------

  #[test]
  fn header_layouts_match_the_spec() {
    assert_eq!(recipient_header(), [0x03, 0x01, 0x01, 0x00]);
    let header = passphrase_header(&Argon2Params::default());
    assert_eq!(&header[..4], &[0x03, 0x02, 0x01, 0x02]);
    assert_eq!(&header[4..8], &3u32.to_be_bytes(), "t_cost BE");
    assert_eq!(&header[8..12], &65536u32.to_be_bytes(), "m_cost BE");
    assert_eq!(header[12], 1, "p");
  }

  #[test]
  fn aad_is_header_then_nul_then_name() {
    let aad = build_aad(&[0x03, 0x01], "KEY");
    assert_eq!(aad, [0x03, 0x01, 0x00, b'K', b'E', b'Y']);
  }

  #[test]
  fn commitment_is_keyed_and_distinct_from_the_key() {
    let a = commitment(&[7u8; KEY_LEN]);
    let b = commitment(&[8u8; KEY_LEN]);
    assert_ne!(a, b, "commitment must depend on the key");
    assert_ne!(a, [7u8; KEY_LEN], "commitment must differ from the key");
  }

  // -- keypair + key schedule ------------------------------------------------

  #[test]
  fn keypair_v3_shapes_and_derivation() {
    let kp = keypair_v3();
    for hex in [&kp.public_key, &kp.private_key] {
      assert_eq!(hex.len(), 64);
      assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
      assert!(hex.bytes().all(|b| !b.is_ascii_uppercase()));
    }
    // The stored private key re-derives the stored public key.
    let secret = StaticSecret::from(parse_key_hex(&kp.private_key).unwrap());
    assert_eq!(
      hex_encode(X25519Public::from(&secret).as_bytes()),
      kp.public_key
    );
  }

  // -- opaque failure paths that need module internals ------------------------

  #[test]
  fn open_rejects_unknown_headers_and_capped_params() {
    let kp = keypair_v3();
    let recipient = parse_key_hex(&kp.public_key).unwrap();

    // Recipient: a mutated header id byte is rejected while the header is
    // read (decrypt-order step 1).
    let mut payload = seal_recipient(&recipient, b"x", "N");
    payload[1] ^= 0x04; // mode → unknown
    assert_eq!(open_recipient(&kp.private_key, &payload, "N"), Err(V3Error));

    // Passphrase: same header-id rejection…
    let payload = seal_passphrase("pw", b"x", "N", &FAST).unwrap();
    let mut bad_header = payload.clone();
    bad_header[2] ^= 0x04; // aead_id → unknown
    assert_eq!(open_passphrase("pw", &bad_header, "N"), Err(V3Error));
    // …and a tampered t_cost above MAX_T_COST is rejected before the KDF
    // ever runs (the anti-DoS ceiling on the read path).
    let mut hot_params = payload;
    hot_params[4] = 0x01; // t_cost 1 → 0x01000001
    assert_eq!(open_passphrase("pw", &hot_params, "N"), Err(V3Error));
  }

  #[test]
  fn non_utf8_plaintext_fails_opaquely_on_open() {
    let kp = keypair_v3();
    let recipient = parse_key_hex(&kp.public_key).unwrap();
    let payload = seal_recipient(&recipient, &[0xff, 0xfe, 0x00], "BYTES");
    assert_eq!(
      open_recipient(&kp.private_key, &payload, "BYTES"),
      Err(V3Error),
      "step 5 strict UTF-8 must fail opaquely"
    );
    let payload = seal_passphrase("pw", &[0xff, 0xfe], "BYTES", &FAST).unwrap();
    assert_eq!(open_passphrase("pw", &payload, "BYTES"), Err(V3Error));
  }

  #[test]
  fn argon2_params_are_validated_and_capped() {
    // Unusable params (m_cost = 0) fail fast and opaquely.
    let zero_m = Argon2Params {
      t_cost: 1,
      m_cost: 0,
      p: 1,
    };
    assert_eq!(argon2id_key("pw", &[0u8; SALT_LEN], &zero_m), Err(V3Error));
    // Valid params but an unusable salt: the derivation itself fails
    // (argon2 requires >= 8 salt bytes) and stays opaque.
    assert_eq!(argon2id_key("pw", &[0u8; 4], &FAST), Err(V3Error));
    // The anti-DoS ceilings hold on the write path too.
    let big_t = Argon2Params {
      t_cost: MAX_T_COST + 1,
      m_cost: 8192,
      p: 1,
    };
    assert_eq!(lock_v3("ab", "x", "pw", "K", &big_t), Err(V3Error));
    let big_m = Argon2Params {
      t_cost: 1,
      m_cost: MAX_M_COST + 1,
      p: 1,
    };
    assert_eq!(lock_v3("ab", "x", "pw", "K", &big_m), Err(V3Error));
  }

  #[test]
  fn v3_error_is_one_opaque_value() {
    assert_eq!(V3Error.to_string(), "v3 crypto operation failed");
    assert_eq!(format!("{V3Error:?}"), "V3Error");
    let as_dyn: &dyn std::error::Error = &V3Error;
    assert!(as_dyn.source().is_none());
    let mapped = opaque_crypto_error(V3Error);
    assert_eq!(mapped.code, Some(CryptoErrorCode::DecryptionFailed));
    assert_eq!(
      mapped.message,
      "[DECRYPTION_FAILED] could not decrypt value"
    );
    assert_eq!(mapped.help, None);
  }

  #[test]
  fn malformed_string_forms_fail_opaquely() {
    let kp = keypair_v3();
    // encrypt: bad recipient hex.
    assert_eq!(encrypt_v3("zz", "v", "K"), Err(V3Error));
    // decrypt: missing prefix / bad base64url / short payload / bad key hex.
    assert_eq!(decrypt_v3(&kp.private_key, "plain", "K"), Err(V3Error));
    assert_eq!(
      decrypt_v3(&kp.private_key, "encrypted:!!!", "K"),
      Err(V3Error)
    );
    assert_eq!(
      decrypt_v3(&kp.private_key, "encrypted:AwEBAA", "K"),
      Err(V3Error),
      "payload below the fixed minimum length"
    );
    let value = encrypt_v3(&kp.public_key, "v", "K").unwrap();
    assert_eq!(decrypt_v3("zz", &value, "K"), Err(V3Error), "bad key hex");
    // unlock: missing prefix / missing payload segment / bad base64url / short.
    assert_eq!(unlock_v3("plain", "pw", "K"), Err(V3Error));
    assert_eq!(unlock_v3("locked:abcd", "pw", "K"), Err(V3Error));
    assert_eq!(unlock_v3("locked:abcd:!!!", "pw", "K"), Err(V3Error));
    assert_eq!(unlock_v3("locked:abcd:AwIBAg", "pw", "K"), Err(V3Error));
  }

  // -- version routing --------------------------------------------------------

  #[test]
  fn decrypt_entry_routes_v3_and_passes_plain_values_through() {
    let kp = keypair_v3();
    let value = encrypt_v3(&kp.public_key, "routed", "NAME").unwrap();
    assert_eq!(
      decrypt_entry(&kp.private_key, &value, "NAME").unwrap(),
      "routed"
    );
    // A v3 failure surfaces as the one uniform coded error.
    let err = decrypt_entry(&kp.private_key, &value, "OTHER").unwrap_err();
    assert_eq!(err.code, Some(CryptoErrorCode::DecryptionFailed));
    assert_eq!(err.message, "[DECRYPTION_FAILED] could not decrypt value");
    // Values without the prefix pass through unchanged.
    assert_eq!(decrypt_entry("", "plain", "NAME").unwrap(), "plain");
    // An empty payload routes to the v1 path (its error taxonomy is kept).
    let err = decrypt_entry(&kp.private_key, "encrypted:", "NAME").unwrap_err();
    assert_eq!(
      err.message, "[DECRYPTION_FAILED] second arg must be public key",
      "the v1 error taxonomy stays intact through the router"
    );
  }

  #[test]
  fn unlock_entry_routes_v3() {
    let kp = keypair_v3();
    let locked = lock_v3(&kp.public_key, "the-plain", "pw", "KEYNAME", &FAST).unwrap();
    assert_eq!(
      unlock_entry(&locked, "pw", "KEYNAME"),
      Some("the-plain".to_string())
    );
    assert_eq!(unlock_entry(&locked, "wrong", "KEYNAME"), None);
    assert_eq!(unlock_entry(&locked, "pw", "OTHER"), None);
    // A payload that is anything else routes to the v1 reader.
    assert_eq!(unlock_entry("locked:abcd:AAAA", "pw", "KEYNAME"), None);
    assert_eq!(unlock_entry("junk", "pw", "KEYNAME"), None);
  }

  // -- property tests (proptest) ---------------------------------------------
  //
  // The v3 reader is an untrusted-input boundary (`encrypted:`/`locked:` values
  // from a .env file). These mirror the `crypto_v3_decrypt` fuzz target's
  // contract as shrinking properties: the codec round-trips, and every decode
  // entry point is total (never panics) on arbitrary input.
  mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// An arbitrary `String` built from arbitrary chars (no regex-feature
    /// dependency), covering the malformed base64url / header surface.
    fn arb_string() -> impl Strategy<Value = String> {
      proptest::collection::vec(any::<char>(), 0..256).prop_map(|v| v.into_iter().collect())
    }

    proptest! {
      /// `base64url_decode(base64url_encode(x)) == x` for every byte vector,
      /// covering all four remainder lengths.
      #[test]
      fn base64url_round_trips(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        prop_assert_eq!(base64url_decode(&base64url_encode(&bytes)), Some(bytes));
      }

      /// `base64url_decode` is total on arbitrary strings — a malformed value is
      /// `None`, never a panic.
      #[test]
      fn base64url_decode_never_panics(s in arb_string()) {
        let _ = base64url_decode(&s);
      }

      /// `hex_decode(hex_encode(x)) == x`.
      #[test]
      fn hex_round_trips(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        prop_assert_eq!(hex_decode(&hex_encode(&bytes)), Some(bytes));
      }

      /// `hex_decode` is total on arbitrary strings.
      #[test]
      fn hex_decode_never_panics(s in arb_string()) {
        let _ = hex_decode(&s);
      }

      /// `first_payload_byte` is total on arbitrary strings.
      #[test]
      fn first_payload_byte_never_panics(s in arb_string()) {
        let _ = first_payload_byte(&s);
      }

      /// Every v3 decode entry point is total on arbitrary strings against a
      /// fixed private key — malformed input yields the opaque error, never a
      /// panic. `unlock` inputs are framed both bare and as `locked:<pub>:<b64>`
      /// so the passphrase branch is reached; the authenticated Argon2 param cap
      /// bounds the KDF work on any header that happens to parse.
      #[test]
      fn v3_decode_entry_points_are_total(s in arb_string()) {
        const PRIV: &str =
          "0202020202020202020202020202020202020202020202020202020202020202";
        // The public hex in a `locked:` frame is echoed, not parsed by the
        // reader, so any 64-hex filler exercises the passphrase branch.
        let pubk = "ab".repeat(32);
        let name = "VAR";
        let _ = decrypt_v3(PRIV, &s, name);
        let _ = decrypt_v3(PRIV, &format!("encrypted:{s}"), name);
        let _ = unlock_v3(&s, "pw", name);
        let _ = unlock_v3(&format!("locked:{pubk}:{s}"), "pw", name);
        let _ = decrypt_entry(PRIV, &s, name);
        let _ = unlock_entry(&s, "pw", name);
      }

      /// Recipient round-trip identity: `decrypt_v3(encrypt_v3(pt)) == pt` for
      /// arbitrary UTF-8 plaintext, sealed and opened under the same name.
      #[test]
      fn recipient_round_trip_is_identity(plaintext in arb_string(), name in arb_string()) {
        let kp = keypair_v3();
        let value = encrypt_v3(&kp.public_key, &plaintext, &name).expect("encrypt");
        prop_assert_eq!(decrypt_v3(&kp.private_key, &value, &name), Ok(plaintext));
      }

      /// A value sealed for one name never opens under a different name
      /// (relocation resistance — the name is bound into the AAD).
      #[test]
      fn recipient_name_binding_holds(plaintext in arb_string(), a in arb_string(), b in arb_string()) {
        prop_assume!(a != b);
        let kp = keypair_v3();
        let value = encrypt_v3(&kp.public_key, &plaintext, &a).expect("encrypt");
        prop_assert_eq!(decrypt_v3(&kp.private_key, &value, &b), Err(V3Error));
      }
    }
  }
}
