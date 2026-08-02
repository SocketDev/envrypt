//! v3 format obligations (docs/envrypt/crypto-v3.md, "Test obligations"):
//! round trips in both modes, opaque failure on wrong key / wrong passphrase /
//! wrong variable name, per-byte header tamper detection, relocation
//! resistance, the commitment check firing before the AEAD, nonce uniqueness
//! across a batch, and header-carried Argon2 params being honored.
//!
//! Loops use reduced Argon2 params (t=1, m=8192 KiB, p=1) to keep the suite
//! fast; exactly one test round-trips the shipped defaults (t=3, m=64 MiB).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use envrypt::crypto_v3::{
    decrypt_entry, decrypt_v3, encrypt_v3, keypair_v3, lock_v3, unlock_entry, unlock_v3,
    Argon2Params, V3Error, MAX_M_COST, MAX_T_COST,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

/// Cheap Argon2id params for loops.
const FAST: Argon2Params = Argon2Params {
    t_cost: 1,
    m_cost: 8192,
    p: 1,
};

/// The plaintext categories every mode must round-trip.
const PLAINTEXTS: &[(&str, &str)] = &[
    ("empty", ""),
    ("ascii", "hello world"),
    ("unicode", "café ☕ 日本語 🔐 Ω"),
    ("control_chars", "line1\nline2\r\ntab\tbell\u{7}end"),
    ("quotes", "$pecial \"quotes\" 'and' \\backslash` ${expand}"),
    (
        "structured",
        "{\"key\":\"value\",\"nested\":{\"n\":42},\"arr\":[1,2,3]}",
    ),
];

// ---------------------------------------------------------------------------
// payload surgery helpers (tamper tests)
// ---------------------------------------------------------------------------

fn b64url_decode(s: &str) -> Vec<u8> {
    fn val(c: u8) -> u8 {
        match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => panic!("invalid base64url char {c:?}"),
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        assert!(chunk.len() >= 2, "lone trailing sextet");
        let mut acc = 0u32;
        for &c in chunk {
            acc = acc << 6 | u32::from(val(c));
        }
        let pad = 4 - chunk.len();
        acc <<= 6 * pad as u32;
        let be = acc.to_be_bytes();
        out.extend_from_slice(&be[1..4 - pad]);
    }
    out
}

fn b64url_encode(bytes: &[u8]) -> String {
    const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
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

/// Decode an `encrypted:<b64url>` value's payload.
fn encrypted_payload(value: &str) -> Vec<u8> {
    b64url_decode(value.strip_prefix("encrypted:").expect("encrypted: form"))
}

/// Re-frame a mutated payload as an `encrypted:` value.
fn reencode_encrypted(payload: &[u8]) -> String {
    format!("encrypted:{}", b64url_encode(payload))
}

/// Decode a `locked:<pub>:<b64url>` value's payload (and keep the frame).
fn locked_payload(value: &str) -> (String, Vec<u8>) {
    let idx = value.rfind(':').expect("locked frame");
    (
        value[..idx + 1].to_string(),
        b64url_decode(&value[idx + 1..]),
    )
}

fn reencode_locked(frame: &str, payload: &[u8]) -> String {
    format!("{frame}{}", b64url_encode(payload))
}

// ---------------------------------------------------------------------------
// round trips
// ---------------------------------------------------------------------------

#[test]
fn recipient_mode_round_trips_every_plaintext_category() {
    let kp = keypair_v3();
    for (name, plaintext) in PLAINTEXTS {
        let var = format!("VAR_{}", name.to_uppercase());
        let value = encrypt_v3(&kp.public_key, plaintext, &var).unwrap();
        assert!(value.starts_with("encrypted:"), "{name}");
        assert_eq!(
            decrypt_v3(&kp.private_key, &value, &var).unwrap(),
            *plaintext,
            "{name}"
        );
    }
    // Long value.
    let long = "x".repeat(10240);
    let value = encrypt_v3(&kp.public_key, &long, "LONG").unwrap();
    assert_eq!(decrypt_v3(&kp.private_key, &value, "LONG").unwrap(), long);
}

#[test]
fn passphrase_mode_round_trips_every_plaintext_category() {
    let kp = keypair_v3();
    for (name, plaintext) in PLAINTEXTS {
        let var = format!("KEY_{}", name.to_uppercase());
        let value = lock_v3(&kp.public_key, plaintext, "pass phrase ✓", &var, &FAST).unwrap();
        assert!(
            value.starts_with(&format!("locked:{}:", kp.public_key)),
            "{name}: the public key is echoed into the frame"
        );
        assert_eq!(
            unlock_v3(&value, "pass phrase ✓", &var).unwrap(),
            *plaintext,
            "{name}"
        );
    }
}

/// The one default-params round trip: t=3, m=65536 KiB (64 MiB), p=1.
#[test]
fn passphrase_mode_round_trips_with_default_params() {
    let kp = keypair_v3();
    let value = lock_v3(
        &kp.public_key,
        &kp.private_key,
        "hunter2",
        "ENVRYPT_PRIVATE_KEY",
        &Argon2Params::default(),
    )
    .unwrap();
    assert_eq!(
        unlock_v3(&value, "hunter2", "ENVRYPT_PRIVATE_KEY").unwrap(),
        kp.private_key
    );
}

#[test]
fn encryption_is_randomized_but_round_trips() {
    let kp = keypair_v3();
    let a = encrypt_v3(&kp.public_key, "same", "K").unwrap();
    let b = encrypt_v3(&kp.public_key, "same", "K").unwrap();
    assert_ne!(a, b, "fresh ephemeral key + nonce per value");
    assert_eq!(decrypt_v3(&kp.private_key, &a, "K").unwrap(), "same");
    assert_eq!(decrypt_v3(&kp.private_key, &b, "K").unwrap(), "same");
}

// ---------------------------------------------------------------------------
// wrong key / wrong passphrase / wrong name → the one opaque error
// ---------------------------------------------------------------------------

#[test]
fn wrong_key_wrong_passphrase_wrong_name_all_fail_opaquely() {
    let kp = keypair_v3();
    let other = keypair_v3();

    let value = encrypt_v3(&kp.public_key, "secret", "NAME").unwrap();
    assert_eq!(
        decrypt_v3(&other.private_key, &value, "NAME"),
        Err(V3Error),
        "wrong key"
    );
    assert_eq!(
        decrypt_v3(&kp.private_key, &value, "NAMe"),
        Err(V3Error),
        "wrong variable name (recipient)"
    );

    let locked = lock_v3(&kp.public_key, "secret", "right", "NAME", &FAST).unwrap();
    assert_eq!(
        unlock_v3(&locked, "wrong", "NAME"),
        Err(V3Error),
        "wrong passphrase"
    );
    assert_eq!(
        unlock_v3(&locked, "right", "NAME2"),
        Err(V3Error),
        "wrong variable name (passphrase)"
    );

    // Every failure renders as the one uniform message. The error text reveals
    // nothing about which check tripped.
    let err = decrypt_v3(&other.private_key, &value, "NAME").unwrap_err();
    assert_eq!(err.to_string(), "v3 crypto operation failed");
}

// ---------------------------------------------------------------------------
// relocation resistance
// ---------------------------------------------------------------------------

#[test]
fn value_sealed_for_name_a_is_bound_to_name_a() {
    let kp = keypair_v3();
    let value = encrypt_v3(&kp.public_key, "false", "DEBUG").unwrap();
    // Moving the value onto another variable fails…
    assert_eq!(
        decrypt_v3(&kp.private_key, &value, "ADMIN_ENABLED"),
        Err(V3Error)
    );
    // …while the original name keeps decrypting.
    assert_eq!(
        decrypt_v3(&kp.private_key, &value, "DEBUG").unwrap(),
        "false"
    );

    let locked = lock_v3(&kp.public_key, "priv", "pw", "KEY_A", &FAST).unwrap();
    assert_eq!(unlock_v3(&locked, "pw", "KEY_B"), Err(V3Error));
    assert_eq!(unlock_v3(&locked, "pw", "KEY_A").unwrap(), "priv");
}

// ---------------------------------------------------------------------------
// header tamper — every byte, individually
// ---------------------------------------------------------------------------

#[test]
fn recipient_header_tamper_fails_for_every_byte() {
    let kp = keypair_v3();
    let value = encrypt_v3(&kp.public_key, "sealed", "VAR").unwrap();
    let payload = encrypted_payload(&value);
    for offset in 0..4 {
        let mut tampered = payload.clone();
        tampered[offset] ^= 0x01;
        assert_eq!(
            decrypt_v3(&kp.private_key, &reencode_encrypted(&tampered), "VAR"),
            Err(V3Error),
            "header byte {offset} tampered"
        );
    }
    // The untouched payload still decrypts (the loop tested real mutations).
    assert_eq!(
        decrypt_v3(&kp.private_key, &reencode_encrypted(&payload), "VAR").unwrap(),
        "sealed"
    );
}

#[test]
fn passphrase_header_tamper_fails_for_every_byte() {
    let kp = keypair_v3();
    let value = lock_v3(&kp.public_key, "sealed", "pw", "VAR", &FAST).unwrap();
    let (frame, payload) = locked_payload(&value);

    // FAST = t=1, m=8192, p=1 → header bytes
    //   [0x03, 0x02, 0x01, 0x02,  0,0,0,1,  0,0,0x20,0,  1]
    // Per-offset tamper values are chosen so the tampered decrypt stays cheap:
    // id bytes (0–3) are rejected while the header is read; KDF-param bytes
    // either exceed the MAX_T_COST/MAX_M_COST anti-DoS ceilings (rejected
    // before the KDF runs) or change the derived key cheaply (the commitment
    // check then fails). Every offset is a real mutation of the stored byte.
    let tamper: &[(usize, u8)] = &[
        (0, 0x02),  // version → unknown
        (1, 0x01),  // mode → recipient (mismatched for this layout)
        (2, 0x02),  // aead_id → unknown
        (3, 0x00),  // kdf_id → none (invalid for passphrase mode)
        (4, 0x01),  // t_cost → 0x01000001 > MAX_T_COST → capped, fast
        (5, 0x01),  // t_cost → 0x00010001 > MAX_T_COST → capped, fast
        (6, 0x01),  // t_cost → 0x00000101 ≤ cap → cheap KDF, commitment fails
        (7, 0x03),  // t_cost → 3 → cheap KDF, commitment fails
        (8, 0x01),  // m_cost → 0x01002000 KiB > MAX_M_COST → capped, fast
        (9, 0x20),  // m_cost → 0x00202000 KiB > MAX_M_COST → capped, fast
        (10, 0x30), // m_cost → 0x00003000 KiB → cheap KDF, commitment fails
        (11, 0x08), // m_cost → 0x00002008 KiB → cheap KDF, commitment fails
        (12, 0x02), // p → 2 lanes → cheap KDF, commitment fails
    ];
    assert_eq!(tamper.len(), 13, "every passphrase header byte is covered");
    for &(offset, new_byte) in tamper {
        let mut tampered = payload.clone();
        assert_ne!(tampered[offset], new_byte, "offset {offset} must change");
        tampered[offset] = new_byte;
        assert_eq!(
            unlock_v3(&reencode_locked(&frame, &tampered), "pw", "VAR"),
            Err(V3Error),
            "header byte {offset} tampered"
        );
    }
    // The untouched payload still unlocks.
    assert_eq!(
        unlock_v3(&reencode_locked(&frame, &payload), "pw", "VAR").unwrap(),
        "sealed"
    );
}

// ---------------------------------------------------------------------------
// commitment: checked before the AEAD
// ---------------------------------------------------------------------------

#[test]
fn corrupted_commitment_fails_even_with_a_valid_aead_body() {
    // Corrupt ONLY the stored commitment: the nonce/tag/ciphertext still form a
    // valid AEAD for the right key, so the failure can come only from the
    // commitment compare — proving it gates the AEAD (spec decrypt order 3–4).
    let kp = keypair_v3();
    let value = encrypt_v3(&kp.public_key, "commit", "VAR").unwrap();
    let mut payload = encrypted_payload(&value);
    let commitment_at = 4 + 32 + 24; // header | eph_pub | nonce
    payload[commitment_at] ^= 0x01;
    assert_eq!(
        decrypt_v3(&kp.private_key, &reencode_encrypted(&payload), "VAR"),
        Err(V3Error)
    );

    let locked = lock_v3(&kp.public_key, "commit", "pw", "VAR", &FAST).unwrap();
    let (frame, mut payload) = locked_payload(&locked);
    let commitment_at = 13 + 16 + 24; // header | salt | nonce
    payload[commitment_at] ^= 0x01;
    assert_eq!(
        unlock_v3(&reencode_locked(&frame, &payload), "pw", "VAR"),
        Err(V3Error)
    );
}

#[test]
fn tag_and_ciphertext_tamper_fail() {
    let kp = keypair_v3();
    let value = encrypt_v3(&kp.public_key, "body", "VAR").unwrap();
    let payload = encrypted_payload(&value);
    let tag_at = 4 + 32 + 24 + 32;
    let ct_at = tag_at + 16;
    for offset in [tag_at, ct_at] {
        let mut tampered = payload.clone();
        tampered[offset] ^= 0x01;
        assert_eq!(
            decrypt_v3(&kp.private_key, &reencode_encrypted(&tampered), "VAR"),
            Err(V3Error),
            "byte {offset} tampered"
        );
    }
}

// ---------------------------------------------------------------------------
// nonce uniqueness
// ---------------------------------------------------------------------------

#[test]
fn nonces_are_unique_across_a_256_value_batch() {
    let kp = keypair_v3();
    let mut nonces = std::collections::HashSet::new();
    let mut eph_pubs = std::collections::HashSet::new();
    for i in 0..256 {
        let value = encrypt_v3(&kp.public_key, "same plaintext", "BATCH").unwrap();
        let payload = encrypted_payload(&value);
        assert!(
            nonces.insert(payload[4 + 32..4 + 32 + 24].to_vec()),
            "nonce repeated at iteration {i}"
        );
        assert!(
            eph_pubs.insert(payload[4..4 + 32].to_vec()),
            "ephemeral key repeated at iteration {i}"
        );
    }
}

#[test]
fn salts_and_nonces_are_unique_across_a_locked_batch() {
    let kp = keypair_v3();
    let mut salts = std::collections::HashSet::new();
    let mut nonces = std::collections::HashSet::new();
    for i in 0..16 {
        let value = lock_v3(&kp.public_key, "same", "pw", "BATCH", &FAST).unwrap();
        let (_, payload) = locked_payload(&value);
        assert!(
            salts.insert(payload[13..13 + 16].to_vec()),
            "salt repeated at iteration {i}"
        );
        assert!(
            nonces.insert(payload[13 + 16..13 + 16 + 24].to_vec()),
            "nonce repeated at iteration {i}"
        );
    }
}

// ---------------------------------------------------------------------------
// Argon2 params live in (and are honored from) the header
// ---------------------------------------------------------------------------

#[test]
fn argon2_params_from_the_header_are_honored() {
    let kp = keypair_v3();
    let custom = Argon2Params {
        t_cost: 2,
        m_cost: 16384,
        p: 2,
    };
    let value = lock_v3(&kp.public_key, "custom params", "pw", "VAR", &custom).unwrap();
    let (_, payload) = locked_payload(&value);
    // The header carries the custom params (t u32 BE, m u32 BE, p u8)…
    assert_eq!(&payload[4..8], &2u32.to_be_bytes(), "t_cost in header");
    assert_eq!(&payload[8..12], &16384u32.to_be_bytes(), "m_cost in header");
    assert_eq!(payload[12], 2, "p in header");
    // …and the decryptor derives with exactly those params.
    assert_eq!(unlock_v3(&value, "pw", "VAR").unwrap(), "custom params");
    // The ceilings themselves are accepted values (boundary check).
    assert!(MAX_T_COST >= custom.t_cost && MAX_M_COST >= custom.m_cost);
}

// ---------------------------------------------------------------------------
// spec-exact probes — the key schedule, commitment, and AEAD re-derived from
// crypto-v3.md using the raw crypto crates (x25519-dalek, hkdf, chacha20poly1305,
// argon2), byte-compared against library output.
// These pin the derivations themselves, which round-trip tests alone cannot:
// a writer/reader pair that agreed on a WRONG key schedule (an ikm that drops
// the ECDH secret, a key derived from something other than the caller's
// passphrase) would still round-trip green. The probes fail it.
// ---------------------------------------------------------------------------

/// Probe-local hex decode for 32-byte keys (the library's own decoder stays
/// out of the independent derivation path).
fn hex32(s: &str) -> [u8; 32] {
    fn val(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("lowercase hex only, got {c:?}"),
        }
    }
    let bytes = s.as_bytes();
    assert_eq!(bytes.len(), 64, "32-byte key hex");
    let mut out = [0u8; 32];
    for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        out[i] = val(pair[0]) << 4 | val(pair[1]);
    }
    out
}

/// `HKDF-SHA256(ikm, salt = ∅, info, len = 32)` exactly as the spec writes it.
fn spec_hkdf(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("32-byte HKDF output");
    okm
}

#[test]
fn recipient_payload_matches_the_spec_key_schedule_byte_for_byte() {
    let kp = keypair_v3();
    let value = encrypt_v3(&kp.public_key, "spec probe", "PROBE").unwrap();
    let payload = encrypted_payload(&value);

    // Layout: header(4) | eph_pub(32) | nonce(24) | commitment(32) | tag(16) | ct.
    assert_eq!(&payload[..4], &[0x03, 0x01, 0x01, 0x00]);
    let eph_pub: [u8; 32] = payload[4..36].try_into().unwrap();
    let nonce = &payload[36..60];
    let stored_commitment = &payload[60..92];
    let tag = &payload[92..108];
    let ciphertext = &payload[108..];

    // Spec key schedule steps 2–3: shared = X25519(recipient_priv, eph_pub);
    // key = HKDF-SHA256(ikm = shared, salt = ∅, info = "envrypt:v3:recip" || eph_pub).
    let secret = StaticSecret::from(hex32(&kp.private_key));
    let shared = secret.diffie_hellman(&X25519Public::from(eph_pub));
    let mut info = b"envrypt:v3:recip".to_vec();
    info.extend_from_slice(&eph_pub);
    let key = spec_hkdf(shared.as_bytes(), &info);

    // The stored commitment re-derives from that exact key — the writer's AEAD
    // key IS the spec's ECDH-derived key (an ikm that ignored the shared secret
    // would commit to a different key and fail here).
    assert_eq!(
        stored_commitment,
        spec_hkdf(&key, b"envrypt:v3:commit"),
        "stored commitment must re-derive from the spec key schedule"
    );

    // Spec step 4: the AEAD opens under that key with the payload nonce and
    // AAD = header || 0x00 || var_name.
    let mut aad = payload[..4].to_vec();
    aad.push(0x00);
    aad.extend_from_slice(b"PROBE");
    let mut ct_and_tag = ciphertext.to_vec();
    ct_and_tag.extend_from_slice(tag);
    let nonce =
        XNonce::from(*<&[u8; 24]>::try_from(nonce).expect("recipient payload nonce is 24 bytes"));
    let plaintext = XChaCha20Poly1305::new(&key.into())
        .decrypt(
            &nonce,
            Payload {
                msg: &ct_and_tag,
                aad: &aad,
            },
        )
        .expect("spec-derived key opens the library's AEAD body");
    assert_eq!(plaintext, b"spec probe");
}

#[test]
fn a_recipient_payload_built_from_the_spec_alone_opens_in_the_library() {
    let kp = keypair_v3();

    // A writer implemented straight from crypto-v3.md using the raw crypto crates.
    let eph_secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let eph_pub = X25519Public::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&X25519Public::from(hex32(&kp.public_key)));
    let mut info = b"envrypt:v3:recip".to_vec();
    info.extend_from_slice(eph_pub.as_bytes());
    let key = spec_hkdf(shared.as_bytes(), &info);
    let commitment = spec_hkdf(&key, b"envrypt:v3:commit");

    let header = [0x03, 0x01, 0x01, 0x00];
    let mut nonce = [0u8; 24];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
    let mut aad = header.to_vec();
    aad.push(0x00);
    aad.extend_from_slice(b"SPEC_BUILT");
    let mut ct_and_tag = XChaCha20Poly1305::new(&key.into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: b"independent writer plaintext".as_slice(),
                aad: &aad,
            },
        )
        .unwrap();
    let tag = ct_and_tag.split_off(ct_and_tag.len() - 16);

    let mut payload = header.to_vec();
    payload.extend_from_slice(eph_pub.as_bytes());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&commitment);
    payload.extend_from_slice(&tag);
    payload.extend_from_slice(&ct_and_tag);

    assert_eq!(
        decrypt_v3(&kp.private_key, &reencode_encrypted(&payload), "SPEC_BUILT").unwrap(),
        "independent writer plaintext",
        "the library reader must open a payload built from the spec alone"
    );
}

#[test]
fn locked_payload_commitment_binds_the_callers_passphrase() {
    let kp = keypair_v3();
    let locked = lock_v3(
        &kp.public_key,
        "locked probe",
        "the real passphrase",
        "PKEY",
        &FAST,
    )
    .unwrap();
    let (_, payload) = locked_payload(&locked);

    // Layout: header(13) | salt(16) | nonce(24) | commitment(32) | tag(16) | ct.
    assert_eq!(&payload[..4], &[0x03, 0x02, 0x01, 0x02]);
    assert_eq!(&payload[4..8], &1u32.to_be_bytes(), "t_cost");
    assert_eq!(&payload[8..12], &8192u32.to_be_bytes(), "m_cost");
    assert_eq!(payload[12], 1, "p");
    let salt = &payload[13..29];
    let nonce = &payload[29..53];
    let stored_commitment = &payload[53..85];
    let tag = &payload[85..101];
    let ciphertext = &payload[101..];

    // Spec: key = Argon2id(passphrase, salt, t, m, p, 32) with the header params.
    let derive = |passphrase: &str| -> [u8; 32] {
        let params = argon2::Params::new(8192, 1, 1, Some(32)).unwrap();
        let argon =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut key = [0u8; 32];
        argon
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .unwrap();
        key
    };

    // The stored commitment re-derives from the CALLER's passphrase…
    let key = derive("the real passphrase");
    assert_eq!(
        stored_commitment,
        spec_hkdf(&key, b"envrypt:v3:commit"),
        "the writer's key must derive from the caller's passphrase"
    );
    // …and a different passphrase's key commits differently, so the stored
    // commitment discriminates passphrases (nothing fixed sits in the schedule).
    let other = derive("a different passphrase");
    assert_ne!(
        stored_commitment,
        spec_hkdf(&other, b"envrypt:v3:commit").as_slice()
    );

    // The AEAD opens under the passphrase-derived key with the spec AAD.
    let mut aad = payload[..13].to_vec();
    aad.push(0x00);
    aad.extend_from_slice(b"PKEY");
    let mut ct_and_tag = ciphertext.to_vec();
    ct_and_tag.extend_from_slice(tag);
    let nonce =
        XNonce::from(*<&[u8; 24]>::try_from(nonce).expect("passphrase payload nonce is 24 bytes"));
    let plaintext = XChaCha20Poly1305::new(&key.into())
        .decrypt(
            &nonce,
            Payload {
                msg: &ct_and_tag,
                aad: &aad,
            },
        )
        .expect("spec-derived Argon2id key opens the library's AEAD body");
    assert_eq!(plaintext, b"locked probe");
}

// ---------------------------------------------------------------------------
// v3 detection leaves v1 untouched
// ---------------------------------------------------------------------------

#[test]
fn v1_values_still_round_trip_through_the_routed_entry_points() {
    // v1 encrypted: written by the crate's own legacy writer, decrypted through
    // the same routed entry point the load pipeline uses.
    let kp1 = envrypt::crypto::keypair();
    let value = envrypt::crypto::encrypt(&kp1.public_key, "v1 plaintext", true).unwrap();
    assert_eq!(
        decrypt_entry(&kp1.private_key, &value, "ANY_NAME").unwrap(),
        "v1 plaintext",
        "the variable name is ignored on the v1 path"
    );
    assert_eq!(
        decrypt_entry(&kp1.private_key, &value, "OTHER_NAME").unwrap(),
        "v1 plaintext"
    );

    // v1 locked: written by the test-support v1 writer, unlocked through the
    // routed entry point.
    let locked = test_support::lock_value_v1(&kp1.public_key, &kp1.private_key, "hunter2");
    assert_eq!(
        unlock_entry(&locked, "hunter2", "ANY_NAME"),
        Some(kp1.private_key.clone())
    );
    assert_eq!(unlock_entry(&locked, "wrong", "ANY_NAME"), None);
}

#[test]
fn load_pipeline_decrypts_v3_values_bound_to_their_names() {
    // End-to-end through the public load()/config() surface: a v3 value sealed
    // for SECRET decrypts during load; the same ciphertext moved onto another
    // variable name stays undecryptable (strict mode errors).
    let kp = keypair_v3();
    let sealed = encrypt_v3(&kp.public_key, "s3cret", "SECRET").unwrap();

    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(
        &env_path,
        format!(
            "ENVRYPT_PUBLIC_KEY=\"{}\"\nSECRET=\"{}\"\n",
            kp.public_key, sealed
        ),
    )
    .unwrap();

    struct FixedKey(String, String);
    impl envrypt::KeyResolver for FixedKey {
        fn resolve(&self, public_key_hex: &str) -> Option<String> {
            (public_key_hex == self.0).then(|| self.1.clone())
        }
    }
    let opts = envrypt::LoadOptions {
        path: Some(vec![env_path.clone()]),
        policy: envrypt::KeyPolicy::Custom(vec![std::sync::Arc::new(FixedKey(
            kp.public_key.clone(),
            kp.private_key.clone(),
        ))]),
        ..Default::default()
    };
    let loaded = envrypt::config(&opts).expect("v3 value decrypts through load()");
    assert_eq!(loaded.get("SECRET"), Some("s3cret"));

    // Relocation: the same ciphertext under a different name fails the load.
    std::fs::write(
        &env_path,
        format!(
            "ENVRYPT_PUBLIC_KEY=\"{}\"\nMOVED=\"{}\"\n",
            kp.public_key, sealed
        ),
    )
    .unwrap();
    let err = envrypt::config(&opts).expect_err("relocated v3 value must stay sealed");
    assert_eq!(err.code(), Some("DECRYPTION_FAILED"));
}
