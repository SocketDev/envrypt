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
