//! The frozen `locked:` v1 decrypt path (`unlock_value`), kept for interop: any
//! `locked:` v1 value unlocks here given the passphrase. Its private helpers
//! `scrypt_key` and `base64url_decode` live alongside it. The interop tripwire
//! (`tests/interop_corpus.rs`) is the coverage.
//!
//! ## Locked value wire format (frozen)
//! `locked:<publicKeyHex>:<base64url(payload)>`, `payload = 0x01 || salt(16) ||
//! iv(12) || gcmTag(16) || ciphertext`, key = `scryptSync(passphrase, salt, 32)`
//! (Node defaults N=16384/log2=14, r=8, p=1), cipher = AES-256-GCM(key, iv). Node
//! stores the 16-byte tag SEPARATELY, BEFORE the ciphertext, while RustCrypto's
//! `aes-gcm` appends it, so [`unlock_value`] reorders accordingly.

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aes::Aes256;
use aes_gcm::AesGcm;
use scrypt::{scrypt, Params};

/// Standard 12-byte-nonce AES-256-GCM (the lock IV length; distinct from the ECIES
/// 16-byte nonce in [`crate::crypto`]).
type Aes256Gcm12 = AesGcm<Aes256, U12>;

const VERSION: u8 = 1;

/// Decodes and decrypts a frozen v1 `locked:` value. A version other than 1, a
/// malformed payload, or a GCM auth failure (wrong passphrase) all yield `None`.
/// The interop tripwire (`tests/interop_corpus.rs`) decrypts the frozen corpus
/// through this path and must stay green.
pub fn unlock_value(locked_private_key: &str, passphrase: &str) -> Option<String> {
  // Everything after `locked:<pub>:` is the payload.
  let mut parts = locked_private_key.splitn(3, ':');
  let _locked = parts.next();
  let _public = parts.next();
  let payload_b64 = parts.next()?;
  let payload = base64url_decode(payload_b64)?;
  if payload.len() < 1 + 16 + 12 + 16 {
    return None;
  }
  let version = payload[0];
  let salt = &payload[1..17];
  let iv = &payload[17..29];
  let tag = &payload[29..45];
  let ciphertext = &payload[45..];
  // Reject any version other than 1 before decrypting.
  if version != VERSION {
    return None;
  }
  let key = scrypt_key(passphrase.as_bytes(), salt);
  let cipher = Aes256Gcm12::new(&key.into());
  // aes-gcm's `decrypt` wants `ciphertext || tag`; reassemble from the stored order.
  let mut sealed = Vec::with_capacity(ciphertext.len() + tag.len());
  sealed.extend_from_slice(ciphertext);
  sealed.extend_from_slice(tag);
  let plaintext = cipher.decrypt(iv.into(), sealed.as_ref()).ok()?;
  String::from_utf8(plaintext).ok()
}

/// Derives a 32-byte key with scrypt at Node's defaults (N=16384, r=8, p=1).
fn scrypt_key(passphrase: &[u8], salt: &[u8]) -> [u8; 32] {
  let params = Params::new(14, 8, 1, 32).expect("valid scrypt params");
  let mut key = [0u8; 32];
  scrypt(passphrase, salt, &params, &mut key).expect("scrypt output length is 32");
  key
}

// ---------------------------------------------------------------------------
// base64url (URL-safe alphabet, no padding) — Node `.toString('base64url')`
// ---------------------------------------------------------------------------

/// Decodes Node's unpadded URL-safe base64 for [`unlock_value`]'s payload.
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
  let bytes: Vec<u8> = s.bytes().filter(|&c| c != b'=').collect();
  let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
  for chunk in bytes.chunks(4) {
    // A lone trailing 6-bit group carries no whole byte (invalid base64url).
    if chunk.len() == 1 {
      return None;
    }
    let mut v = 0u32;
    for &c in chunk {
      v = (v << 6) | val(c)? as u32;
    }
    let pad = 4 - chunk.len();
    v <<= 6 * pad as u32;
    // `v` now holds a big-endian 24-bit group in its low 3 bytes.
    let be = v.to_be_bytes();
    for byte in be.iter().skip(1).take(3 - pad) {
      out.push(*byte);
    }
  }
  Some(out)
}

#[cfg(test)]
mod tests {
  use super::*;

  // Negative paths that need no encoder. Positive round-trip coverage lives in
  // the interop tripwire, `tests/interop_corpus.rs`, which unlocks the frozen
  // v1 corpus.
  #[test]
  fn unlock_rejects_malformed_payloads() {
    // Not base64url after `locked:<pub>:`.
    assert!(unlock_value("locked:02abc:!!!notb64", "x").is_none());
    // Missing the payload segment entirely.
    assert!(unlock_value("locked:02abc", "x").is_none());
    // Too-short payload (decodes but < 1+16+12+16 bytes).
    assert!(unlock_value("locked:02abc:AAAA", "x").is_none());
  }
}
