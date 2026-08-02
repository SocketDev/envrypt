use super::*;

/// Keypair A used across these tests.
const PUBLIC_KEY: &str = "02b106c30579baf896ae1fddf077cbcb4fef5e7d457932974878dcb51f42b45498";
const PRIVATE_KEY: &str = "1fc1cafa954a7a2bf0a6fbff46189c9e03e3a66b4d1133108ab9fcdb9e154b70";

/// A hardcoded golden ciphertext for keypair A that decrypts to `expanded`.
const GOLDEN_EXPANDED: &str = "encrypted:BMVCQpz/+NYDcGZhbXyqbwP8IDJSTXl4xDQsgusQHEVFAWOXQnKRBTOzRiwuYIJzjuWnKkrQJEDEi8Av9xnfx61jVTJymVWLjVmFK7CM+6lmKOnIhPMzu0Mi0dH82P81bOXjkZTHIIcA";

/// A malformed-data vector whose first payload byte 0x00 is not a curve point.
const MALFORMED_VECTOR: &str = "encrypted:ADJIvD6DxJdTcFdg1tcasYa9G1O5YVtFJs0yJgem+aGIlRJl9N1Fbq6kdPtIwfS0c6VJF4EN6H+D0JUwJ4FmoerQi0XQ4mv4AyA73KjrxVEqmSypg2InsV0e4WxdP5Qx/jVVSgxD";

fn golden_payload() -> Vec<u8> {
    node_base64_decode(&GOLDEN_EXPANDED[ENCRYPTED_PREFIX.len()..])
}

fn reencode(payload: &[u8]) -> String {
    format!("{}{}", ENCRYPTED_PREFIX, base64_encode(payload))
}

mod decrypt_key_value_tests {
    use super::*;

    #[test]
    fn decrypt_key_value_decrypts() {
        let encrypted_string = encrypt(PUBLIC_KEY, "hello", true).unwrap();
        let decrypted = decrypt_key_value(
            "KEY",
            &encrypted_string,
            "ENVRYPT_PRIVATE_KEY",
            Some(PRIVATE_KEY),
        )
        .unwrap();
        assert_eq!(decrypted, "hello");
    }

    #[test]
    fn decrypt_key_value_private_key_null() {
        let encrypted_string = encrypt(PUBLIC_KEY, "hello", true).unwrap();
        let error = decrypt_key_value(
            "KEY",
            &encrypted_string,
            "ENVRYPT_PRIVATE_KEY_PRODUCTION",
            None,
        )
        .unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::MissingPrivateKey));
        assert_eq!(
              error.message,
              "[MISSING_PRIVATE_KEY] could not decrypt KEY using private key 'ENVRYPT_PRIVATE_KEY_PRODUCTION='"
          );
        assert_eq!(
            error.help.as_deref(),
            Some("fix: [https://github.com/SocketDev/envrypt/issues/464]")
        );
    }

    #[test]
    fn decrypt_key_value_does_not_start_with_encrypted_returns_raw_value() {
        let decrypted =
            decrypt_key_value("KEY", "world", "ENVRYPT_PRIVATE_KEY", Some(PRIVATE_KEY)).unwrap();
        assert_eq!(decrypted, "world"); // return the original raw value
    }

    #[test]
    fn decrypt_key_value_invalid_short_encrypted_value_raises_error() {
        let error = decrypt_key_value(
            "KEY",
            "encrypted:1234",
            "ENVRYPT_PRIVATE_KEY",
            Some(PRIVATE_KEY),
        )
        .unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::DecryptionFailed));
        assert_eq!(
            error.message,
            "[DECRYPTION_FAILED] second arg must be public key"
        );
    }

    #[test]
    fn decrypt_key_value_invalid_encrypted_value_raises_error() {
        let error = decrypt_key_value(
            "KEY",
            MALFORMED_VECTOR,
            "ENVRYPT_PRIVATE_KEY",
            Some(PRIVATE_KEY),
        )
        .unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::MalformedEncryptedData));
        assert_eq!(
      error.message,
      "[MALFORMED_ENCRYPTED_DATA] could not decrypt KEY because encrypted data appears malformed"
    );
    }

    // A 33-byte payload parses as a compressed ephemeral point; a parse
    // failure there carries the `bad point:` prefix, which
    // `decrypt_key_value` re-maps to MALFORMED_ENCRYPTED_DATA.
    #[test]
    fn decrypt_key_value_33_byte_bad_point_maps_to_malformed() {
        let truncated = reencode(&golden_payload()[..33]);
        let error = decrypt_key_value("KEY", &truncated, "ENVRYPT_PRIVATE_KEY", Some(PRIVATE_KEY))
            .unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::MalformedEncryptedData));
        assert_eq!(
      error.message,
      "[MALFORMED_ENCRYPTED_DATA] could not decrypt KEY because encrypted data appears malformed"
    );
        assert_eq!(
            error.help.as_deref(),
            Some("fix: [https://github.com/SocketDev/envrypt/issues/467]")
        );
    }

    // A VALID 33-byte compressed point parses, so the failure comes from the
    // empty symmetric layer and keeps the DECRYPTION_FAILED code rather than
    // the malformed re-map.
    #[test]
    fn decrypt_key_value_valid_compressed_point_payload_is_decryption_failed() {
        let point = strict_hex_decode(PUBLIC_KEY).unwrap();
        let error = decrypt_key_value(
            "KEY",
            &reencode(&point),
            "ENVRYPT_PRIVATE_KEY",
            Some(PRIVATE_KEY),
        )
        .unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::DecryptionFailed));
        assert_eq!(
            error.message,
            "[DECRYPTION_FAILED] Invalid initialization vector"
        );
        assert_eq!(
            error.help.as_deref(),
            Some("fix: [https://github.com/SocketDev/envrypt/issues/757]")
        );
    }

    #[test]
    fn decrypt_key_value_invalid_empty_encrypted_value_raises_error() {
        let error = decrypt_key_value(
            "KEY",
            "encrypted:",
            "ENVRYPT_PRIVATE_KEY",
            Some(PRIVATE_KEY),
        )
        .unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::DecryptionFailed));
        assert_eq!(
            error.message,
            "[DECRYPTION_FAILED] second arg must be public key"
        );
    }

    #[test]
    fn decrypt_key_value_invalid_private_key() {
        let encrypted_string = encrypt(PUBLIC_KEY, "hello", true).unwrap();
        let error = decrypt_key_value(
            "KEY",
            &encrypted_string,
            "ENVRYPT_PRIVATE_KEY",
            Some("invalid-private-key"),
        )
        .unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::InvalidPrivateKey));
        assert_eq!(
              error.message,
              "[INVALID_PRIVATE_KEY] could not decrypt KEY using private key 'ENVRYPT_PRIVATE_KEY=invalid…'"
          );
    }

    #[test]
    fn decrypt_key_value_empty_private_key() {
        let encrypted_string = encrypt(PUBLIC_KEY, "hello", true).unwrap();
        let error = decrypt_key_value("KEY", &encrypted_string, "ENVRYPT_PRIVATE_KEY", Some(""))
            .unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::MissingPrivateKey));
        assert_eq!(
            error.message,
            "[MISSING_PRIVATE_KEY] could not decrypt KEY using private key 'ENVRYPT_PRIVATE_KEY='"
        );
        assert_eq!(
            error.help.as_deref(),
            Some("fix: [https://github.com/SocketDev/envrypt/issues/464]")
        );
    }

    #[test]
    fn decrypt_key_value_wrong_private_key() {
        let encrypted_string = encrypt(PUBLIC_KEY, "hello", true).unwrap();
        let error = decrypt_key_value(
            "KEY",
            &encrypted_string,
            "ENVRYPT_PRIVATE_KEY",
            Some("9c1ab41477004e68066129a8866887d316ba5d7177593dbc5e3026d6f64d32f8"),
        )
        .unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::WrongPrivateKey));
        assert_eq!(
      error.message,
      "[WRONG_PRIVATE_KEY] could not decrypt KEY using private key 'ENVRYPT_PRIVATE_KEY=9c1ab41…'"
    );
    }

    #[test]
    fn decrypt_key_value_when_empty_string() {
        let encrypted_string = encrypt(PUBLIC_KEY, "", true).unwrap();
        let decrypted = decrypt_key_value(
            "KEY",
            &encrypted_string,
            "ENVRYPT_PRIVATE_KEY",
            Some(PRIVATE_KEY),
        )
        .unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn decrypt_key_value_hardcoded_scenario() {
        let decrypted = decrypt_key_value(
            "KEY",
            GOLDEN_EXPANDED,
            "ENVRYPT_PRIVATE_KEY",
            Some(PRIVATE_KEY),
        )
        .unwrap();
        assert_eq!(decrypted, "expanded");
    }

    // Multi-key scenario encoded in decryptKeyValue.js:23-40 (comma-separated
    // private keys; any success resets the error).
    #[test]
    fn decrypt_key_value_multiple_private_keys_second_wins() {
        let encrypted_string = encrypt(PUBLIC_KEY, "hello", true).unwrap();
        let keys = format!(
            "9c1ab41477004e68066129a8866887d316ba5d7177593dbc5e3026d6f64d32f8,{PRIVATE_KEY}"
        );
        let decrypted =
            decrypt_key_value("KEY", &encrypted_string, "ENVRYPT_PRIVATE_KEY", Some(&keys))
                .unwrap();
        assert_eq!(decrypted, "hello");
    }

    // Last failure wins when every comma-separated key fails; the truncated
    // display uses the FULL original comma-joined string (decryptKeyValue.js:31-37).
    #[test]
    fn decrypt_key_value_multiple_private_keys_all_fail() {
        let encrypted_string = encrypt(PUBLIC_KEY, "hello", true).unwrap();
        let keys =
            "9c1ab41477004e68066129a8866887d316ba5d7177593dbc5e3026d6f64d32f8,invalid-private-key";
        let error = decrypt_key_value("KEY", &encrypted_string, "ENVRYPT_PRIVATE_KEY", Some(keys))
            .unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::InvalidPrivateKey));
        assert_eq!(
              error.message,
              "[INVALID_PRIVATE_KEY] could not decrypt KEY using private key 'ENVRYPT_PRIVATE_KEY=9c1ab41…'"
          );
    }
}

// `encrypt_with_key` over a once-parsed recipient matches `encrypt`: both
// round-trip to the same plaintext (ciphertext is randomized, so compare the
// decrypt, never the bytes), and the parse surface rejects a bad key the same
// way.
mod hoist {
    use super::*;

    #[test]
    fn encrypt_with_key_matches_encrypt_semantics() {
        let recipient = parse_public_key(PUBLIC_KEY).unwrap();
        for (value, prefix) in [("hello", true), ("multi\nline", true), ("device", false)] {
            let via_hoist = encrypt_with_key(&recipient, value, prefix);
            assert_eq!(via_hoist.starts_with(ENCRYPTED_PREFIX), prefix);
            assert_eq!(decrypt(PRIVATE_KEY, &via_hoist, prefix).unwrap(), value);
            // `encrypt` delegates to `encrypt_with_key`: the public entry
            // round-trips identically.
            let via_encrypt = encrypt(PUBLIC_KEY, value, prefix).unwrap();
            assert_eq!(decrypt(PRIVATE_KEY, &via_encrypt, prefix).unwrap(), value);
        }
    }

    #[test]
    fn parse_public_key_rejects_malformed_like_encrypt() {
        let via_parse = parse_public_key("not-hex").unwrap_err();
        let via_encrypt = encrypt("not-hex", "x", true).unwrap_err();
        assert_eq!(via_parse.message, via_encrypt.message);
        assert!(via_parse.code.is_none(), "raw (uncoded) error");
    }
}

// One test per error-mapping row. Expected strings checked on Node v26,
// 2026-07-11.
mod error_mapping {
    use super::*;

    // A truncated payload (< 65 B and not exactly 33 B: the ephemeral-key
    // slice fails the length pre-check) → DECRYPTION_FAILED with the exact
    // wrong-length message.
    #[test]
    fn truncated_payload_maps_to_decryption_failed() {
        let error = decrypt(PRIVATE_KEY, "encrypted:1234", true).unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::DecryptionFailed));
        assert_eq!(
            error.message,
            "[DECRYPTION_FAILED] second arg must be public key"
        );
        assert_eq!(
              error.message_with_help(),
              "[DECRYPTION_FAILED] second arg must be public key. fix: [https://github.com/SocketDev/envrypt/issues/757]"
          );
    }

    // GCM tag mismatch (flipped tag bit) → WRONG_PRIVATE_KEY.
    #[test]
    fn flipped_tag_bit_maps_to_wrong_private_key() {
        let mut payload = golden_payload();
        payload[EPHEMERAL_PUBLIC_KEY_LEN + NONCE_LEN] ^= 1; // first tag byte
        let error = decrypt(PRIVATE_KEY, &reencode(&payload), true).unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::WrongPrivateKey));
        assert_eq!(
            error.message,
            "[WRONG_PRIVATE_KEY] could not decrypt using private key"
        );
    }

    // GCM auth failure via flipped ciphertext bit → WRONG_PRIVATE_KEY too.
    #[test]
    fn flipped_ciphertext_bit_maps_to_wrong_private_key() {
        let mut payload = golden_payload();
        payload[EPHEMERAL_PUBLIC_KEY_LEN + NONCE_LEN + TAG_LEN] ^= 1; // first ct byte
        let error = decrypt(PRIVATE_KEY, &reencode(&payload), true).unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::WrongPrivateKey));
    }

    // wrong (but valid) key → WRONG_PRIVATE_KEY (tag mismatch condition).
    #[test]
    fn wrong_key_maps_to_wrong_private_key() {
        let error = decrypt(
            "9c1ab41477004e68066129a8866887d316ba5d7177593dbc5e3026d6f64d32f8",
            GOLDEN_EXPANDED,
            true,
        )
        .unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::WrongPrivateKey));
        assert_eq!(
            error.message,
            "[WRONG_PRIVATE_KEY] could not decrypt using private key"
        );
        assert_eq!(
              error.message_with_help(),
              "[WRONG_PRIVATE_KEY] could not decrypt using private key. fix: [https://github.com/SocketDev/envrypt/issues/466]"
          );
    }

    // An ephemeral-point parse failure at the crypto layer surfaces as
    // DECRYPTION_FAILED with the message embedded verbatim; only
    // [`decrypt_key_value`] re-maps `bad point:` to MALFORMED_ENCRYPTED_DATA
    // (see the decrypt_key_value tests). MALFORMED_VECTOR's first payload byte
    // is 0x00, so the sliced 65-byte ephemeral key fails the head check.
    #[test]
    fn bad_point_maps_to_decryption_failed_with_noble_message() {
        let error = decrypt(PRIVATE_KEY, MALFORMED_VECTOR, true).unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::DecryptionFailed));
        assert_eq!(
      error.message,
      "[DECRYPTION_FAILED] bad point: got length 65, expected compressed=33 or uncompressed=65"
    );
        assert_eq!(
              error.message_with_help(),
              "[DECRYPTION_FAILED] bad point: got length 65, expected compressed=33 or uncompressed=65. fix: [https://github.com/SocketDev/envrypt/issues/757]"
          );
    }

    // Every ephemeral-point-parse message variant, verbatim (checked on Node
    // v26, 2026-07-11). The parser accepts 33-byte COMPRESSED points, so a
    // length-33 payload parses as a compressed ephemeral key.
    #[test]
    fn ephemeral_point_parse_failures_reproduce_noble_messages() {
        let golden = golden_payload();

        // 33-byte payload whose head byte is not 0x02/0x03 (truncating the
        // golden payload leaves the uncompressed 0x04 head).
        let error = decrypt(PRIVATE_KEY, &reencode(&golden[..33]), true).unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::DecryptionFailed));
        assert_eq!(
      error.message,
      "[DECRYPTION_FAILED] bad point: got length 33, expected compressed=33 or uncompressed=65"
    );

        // 33-byte compressed head with x ≥ p.
        let mut wrong_x = vec![0x02u8];
        wrong_x.extend_from_slice(&[0xff; 32]);
        let error = decrypt(PRIVATE_KEY, &reencode(&wrong_x), true).unwrap_err();
        assert_eq!(
            error.message,
            "[DECRYPTION_FAILED] bad point: is not on curve, wrong x"
        );

        // 33-byte compressed head with x < p but x³+7 a non-residue (x = 5).
        let mut sqrt_fail = vec![0u8; 33];
        sqrt_fail[0] = 0x02;
        sqrt_fail[32] = 0x05;
        let error = decrypt(PRIVATE_KEY, &reencode(&sqrt_fail), true).unwrap_err();
        assert_eq!(
            error.message,
            "[DECRYPTION_FAILED] bad point: is not on curve, sqrt error: Cannot find square root"
        );

        // 65-byte uncompressed head with off-curve coordinates (flipped y
        // bit in the full-length golden payload).
        let mut y_flipped = golden.clone();
        y_flipped[64] ^= 1;
        let error = decrypt(PRIVATE_KEY, &reencode(&y_flipped), true).unwrap_err();
        assert_eq!(
            error.message,
            "[DECRYPTION_FAILED] bad point: is not on curve"
        );

        // 65-byte slice whose head is a compressed prefix.
        let mut head02 = golden[..65].to_vec();
        head02[0] = 0x02;
        let error = decrypt(PRIVATE_KEY, &reencode(&head02), true).unwrap_err();
        assert_eq!(
      error.message,
      "[DECRYPTION_FAILED] bad point: got length 65, expected compressed=33 or uncompressed=65"
    );
    }

    // A payload that IS exactly a valid 33-byte compressed point parses as
    // the ephemeral key; the symmetric portion is then empty and fails with
    // Node's `Invalid initialization vector` (checked 2026-07-11).
    #[test]
    fn valid_compressed_point_payload_fails_at_symmetric_layer() {
        let point = strict_hex_decode(PUBLIC_KEY).unwrap();
        assert_eq!(point.len(), 33);
        let error = decrypt(PRIVATE_KEY, &reencode(&point), true).unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::DecryptionFailed));
        assert_eq!(
            error.message,
            "[DECRYPTION_FAILED] Invalid initialization vector"
        );
    }

    // bad-hex key → INVALID_PRIVATE_KEY (scalar validation condition).
    #[test]
    fn bad_hex_key_maps_to_invalid_private_key() {
        for bad in [
            "invalid-private-key",
            "abcd",                                                             // short
            "0000000000000000000000000000000000000000000000000000000000000000", // zero
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // ≥ n
            "1fc1cafa954a7a2bf0a6fbff46189c9e03e3a66b4d1133108ab9fcdb9e154b7",  // odd length
        ] {
            let error = decrypt(bad, GOLDEN_EXPANDED, true).unwrap_err();
            assert_eq!(
                error.code,
                Some(CryptoErrorCode::InvalidPrivateKey),
                "key {bad:?} must map to INVALID_PRIVATE_KEY"
            );
            assert_eq!(
                error.message,
                "[INVALID_PRIVATE_KEY] could not decrypt using private key"
            );
        }
    }

    // empty key → MISSING_PRIVATE_KEY.
    #[test]
    fn empty_key_maps_to_missing_private_key() {
        let error = decrypt("", GOLDEN_EXPANDED, true).unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::MissingPrivateKey));
        assert_eq!(
            error.message,
            "[MISSING_PRIVATE_KEY] could not decrypt because private key is missing"
        );
        assert_eq!(
              error.message_with_help(),
              "[MISSING_PRIVATE_KEY] could not decrypt because private key is missing. fix: [https://github.com/SocketDev/envrypt/issues/464]"
          );
    }

    // Symmetric-layer truncations with a VALID leading point (Node error
    // strings reproduced verbatim):
    //   payload == 65 B (empty nonce)       → "Invalid initialization vector"
    //   65 < payload < 97 (short nonce/tag) → "Invalid authentication tag length: N"
    // where N follows Node's observed table: t = payload_len - 81 clamped at 0;
    // N = 0 for t == 0 else min(t, 16 - t).
    #[test]
    fn truncated_symmetric_payload_messages() {
        let payload = golden_payload();
        let cases: &[(usize, &str)] = &[
            (65, "[DECRYPTION_FAILED] Invalid initialization vector"),
            (
                66,
                "[DECRYPTION_FAILED] Invalid authentication tag length: 0",
            ),
            (
                70,
                "[DECRYPTION_FAILED] Invalid authentication tag length: 0",
            ),
            (
                81,
                "[DECRYPTION_FAILED] Invalid authentication tag length: 0",
            ),
            (
                82,
                "[DECRYPTION_FAILED] Invalid authentication tag length: 1",
            ),
            (
                89,
                "[DECRYPTION_FAILED] Invalid authentication tag length: 8",
            ),
            (
                90,
                "[DECRYPTION_FAILED] Invalid authentication tag length: 7",
            ),
            (
                96,
                "[DECRYPTION_FAILED] Invalid authentication tag length: 1",
            ),
        ];
        for &(len, expected) in cases {
            let error = decrypt(PRIVATE_KEY, &reencode(&payload[..len]), true).unwrap_err();
            assert_eq!(error.code, Some(CryptoErrorCode::DecryptionFailed));
            assert_eq!(error.message, expected, "payload truncated to {len} bytes");
        }
    }

    // Exhaustive truncation sweep: every prefix of the golden payload maps to
    // the exact code + message (checked on Node v26 for all lengths 0-105,
    // 2026-07-11). Pins the length/head semantics, in particular the 33-byte
    // compressed-length case, where the truncated golden payload (0x04 head)
    // is a point-parse failure rather than a length failure.
    #[test]
    fn truncation_sweep_matches_reference() {
        let payload = golden_payload();
        assert_eq!(payload.len(), 105);
        for len in 0..=payload.len() {
            let result = decrypt(PRIVATE_KEY, &reencode(&payload[..len]), true);
            match len {
                105 => assert_eq!(result.unwrap(), "expanded"),
                // ciphertext truncated → GCM auth failure.
                97..=104 => {
                    let error = result.unwrap_err();
                    assert_eq!(
                        error.code,
                        Some(CryptoErrorCode::WrongPrivateKey),
                        "len {len}"
                    );
                    assert_eq!(
                        error.message, "[WRONG_PRIVATE_KEY] could not decrypt using private key",
                        "len {len}"
                    );
                }
                // exactly compressed length, but head byte is 0x04.
                33 => {
                    let error = result.unwrap_err();
                    assert_eq!(
                        error.code,
                        Some(CryptoErrorCode::DecryptionFailed),
                        "len {len}"
                    );
                    assert_eq!(
                          error.message,
                          "[DECRYPTION_FAILED] bad point: got length 33, expected compressed=33 or uncompressed=65",
                          "len {len}"
                      );
                }
                // length pre-check rejects a short ephemeral-key slice.
                0..=64 => {
                    let error = result.unwrap_err();
                    assert_eq!(
                        error.code,
                        Some(CryptoErrorCode::DecryptionFailed),
                        "len {len}"
                    );
                    assert_eq!(
                        error.message, "[DECRYPTION_FAILED] second arg must be public key",
                        "len {len}"
                    );
                }
                // valid point, empty symmetric data.
                65 => {
                    let error = result.unwrap_err();
                    assert_eq!(
                        error.message, "[DECRYPTION_FAILED] Invalid initialization vector",
                        "len {len}"
                    );
                }
                // short nonce/tag → Node's tag-length table.
                66..=96 => {
                    let t = len.saturating_sub(65 + NONCE_LEN);
                    let n = if t == 0 { 0 } else { t.min(16 - t) };
                    let error = result.unwrap_err();
                    assert_eq!(
                        error.code,
                        Some(CryptoErrorCode::DecryptionFailed),
                        "len {len}"
                    );
                    assert_eq!(
                        error.message,
                        format!("[DECRYPTION_FAILED] Invalid authentication tag length: {n}"),
                        "len {len}"
                    );
                }
                _ => unreachable!(),
            }
        }
    }

    // Garbage after the prefix: Node's lenient base64 decoder yields a short
    // payload rather than a decode error.
    #[test]
    fn garbage_base64_maps_to_decryption_failed() {
        let error = decrypt(PRIVATE_KEY, "encrypted:!!!not-base64!!!", true).unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::DecryptionFailed));
        assert_eq!(
            error.message,
            "[DECRYPTION_FAILED] second arg must be public key"
        );
    }

    // Invalid key precedence: key parsing happens before payload inspection,
    // so INVALID_PRIVATE_KEY wins over malformed data.
    #[test]
    fn invalid_key_takes_precedence_over_malformed_payload() {
        let error = decrypt("invalid-private-key", MALFORMED_VECTOR, true).unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::InvalidPrivateKey));
    }
}

// Pass-through semantics.
mod passthrough {
    use super::*;

    #[test]
    fn decrypt_of_non_prefixed_value_returns_it_unchanged() {
        assert_eq!(decrypt(PRIVATE_KEY, "world", true).unwrap(), "world");
        assert_eq!(decrypt(PRIVATE_KEY, "", true).unwrap(), "");
        // Pass-through happens BEFORE the missing-key check.
        assert_eq!(decrypt("", "plain-value", true).unwrap(), "plain-value");
    }

    #[test]
    fn decrypt_with_key_passes_through_non_prefixed_values() {
        let secret = parse_private_key(PRIVATE_KEY).unwrap();
        assert_eq!(decrypt_with_key(&secret, "world", true).unwrap(), "world");
    }

    #[test]
    fn is_encrypted_predicate() {
        assert!(is_encrypted("encrypted:abc"));
        assert!(is_encrypted("encrypted:")); // no payload validation
        assert!(!is_encrypted(""));
        assert!(!is_encrypted("world"));
        assert!(!is_encrypted("ENCRYPTED:abc")); // case-sensitive
    }
}

// Wire format and key basics.
mod wire_format {
    use super::*;

    #[test]
    fn keypair_shapes() {
        let kp = keypair();
        assert_eq!(kp.public_key.len(), 66);
        assert!(kp.public_key.starts_with("02") || kp.public_key.starts_with("03"));
        assert_eq!(kp.private_key.len(), 64);
        assert!(kp.public_key.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(kp.private_key.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(kp.public_key.bytes().all(|b| !b.is_ascii_uppercase()));
        // derive() recovers the compressed public key.
        assert_eq!(derive(&kp.private_key).unwrap(), kp.public_key);
    }

    #[test]
    fn derive_golden() {
        assert_eq!(derive(PRIVATE_KEY).unwrap(), PUBLIC_KEY);
    }

    // derive returns the raw (uncoded) `Invalid private key`.
    #[test]
    fn derive_invalid_private_key_is_raw_error() {
        for bad in [
            "invalid",
            "",
            "00",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ] {
            let error = derive(bad).unwrap_err();
            assert_eq!(error.code, None, "derive({bad:?})");
            assert_eq!(error.message, "Invalid private key");
            assert_eq!(error.help, None);
            assert_eq!(error.message_with_help(), "Invalid private key");
        }
    }

    #[test]
    fn parse_private_key_maps_to_invalid_private_key_condition() {
        let error = parse_private_key("invalid").unwrap_err();
        assert_eq!(error.code, Some(CryptoErrorCode::InvalidPrivateKey));
        let secret = parse_private_key(PRIVATE_KEY).unwrap();
        assert_eq!(public_key_hex(&secret), PUBLIC_KEY);
    }

    // payload = 65 + 16 + 16 + len(plaintext); ephemeral key is 0x04-prefixed
    // uncompressed; base64 is standard alphabet with padding.
    #[test]
    fn encrypt_payload_structure() {
        for plaintext in ["", "x", "hello world", "line 1\nline 2"] {
            let value = encrypt(PUBLIC_KEY, plaintext, true).unwrap();
            assert!(value.starts_with(ENCRYPTED_PREFIX));
            let payload = node_base64_decode(&value[ENCRYPTED_PREFIX.len()..]);
            assert_eq!(
                payload.len(),
                EPHEMERAL_PUBLIC_KEY_LEN + NONCE_LEN + TAG_LEN + plaintext.len(),
                "payload length for {plaintext:?}"
            );
            assert_eq!(payload[0], 0x04, "ephemeral key must be uncompressed");
        }
    }

    #[test]
    fn encrypt_prefix_false_returns_bare_base64() {
        let bare = encrypt(PUBLIC_KEY, "hello", false).unwrap();
        assert!(!bare.starts_with(ENCRYPTED_PREFIX));
        // Same payload semantics — decryptable once re-prefixed.
        assert_eq!(
            decrypt(PRIVATE_KEY, &format!("{ENCRYPTED_PREFIX}{bare}"), true).unwrap(),
            "hello"
        );
        assert_eq!(decrypt(PRIVATE_KEY, &bare, false).unwrap(), "hello");
    }

    // Randomized encryption: two encryptions of the same plaintext differ
    // (fresh ephemeral key + nonce); both round-trip.
    #[test]
    fn encryption_is_randomized() {
        let a = encrypt(PUBLIC_KEY, "same", true).unwrap();
        let b = encrypt(PUBLIC_KEY, "same", true).unwrap();
        assert_ne!(a, b);
        assert_eq!(decrypt(PRIVATE_KEY, &a, true).unwrap(), "same");
        assert_eq!(decrypt(PRIVATE_KEY, &b, true).unwrap(), "same");
    }

    // encrypt accepts the 130-hex uncompressed form too.
    #[test]
    fn encrypt_accepts_uncompressed_public_key() {
        let secret = parse_private_key(PRIVATE_KEY).unwrap();
        let uncompressed = secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(uncompressed.len(), 130);
        let value = encrypt(&uncompressed, "hello", true).unwrap();
        assert_eq!(decrypt(PRIVATE_KEY, &value, true).unwrap(), "hello");
    }

    // encrypt-side failures are raw (uncoded) errors (checked 2026-07-11).
    #[test]
    fn encrypt_bad_public_key_errors() {
        let e = encrypt("zz", "x", true).unwrap_err();
        assert_eq!(e.code, None);
        assert_eq!(
            e.message,
            "Input string must contain hex characters in even length"
        );

        let e = encrypt("02b1c", "x", true).unwrap_err(); // odd length
        assert_eq!(
            e.message,
            "Input string must contain hex characters in even length"
        );

        let e = encrypt("", "x", true).unwrap_err(); // wrong byte length
        assert_eq!(e.message, "second arg must be public key");
        let e = encrypt("02b1", "x", true).unwrap_err();
        assert_eq!(e.message, "second arg must be public key");

        // compressed length, x ≥ p
        let bad_point = format!("02{}", "ff".repeat(32));
        let e = encrypt(&bad_point, "x", true).unwrap_err();
        assert_eq!(e.code, None);
        assert_eq!(e.message, "bad point: is not on curve, wrong x");

        // compressed length, x < p, x³+7 a non-residue
        let e = encrypt(&format!("02{}05", "00".repeat(31)), "x", true).unwrap_err();
        assert_eq!(
            e.message,
            "bad point: is not on curve, sqrt error: Cannot find square root"
        );

        // compressed length, head byte not 0x02/0x03
        let e = encrypt(&format!("04{}", "00".repeat(32)), "x", true).unwrap_err();
        assert_eq!(
            e.message,
            "bad point: got length 33, expected compressed=33 or uncompressed=65"
        );

        // uncompressed length, head byte not 0x04
        let e = encrypt(&"00".repeat(65), "x", true).unwrap_err();
        assert_eq!(
            e.message,
            "bad point: got length 65, expected compressed=33 or uncompressed=65"
        );

        // uncompressed length, coordinates off curve / out of range
        let e = encrypt(&format!("04{}", "ff".repeat(64)), "x", true).unwrap_err();
        assert_eq!(e.message, "bad point: is not on curve");
    }

    #[test]
    fn unicode_round_trips() {
        for plaintext in ["🚀🔐", "こんにちは世界", "héllo wörld ñ", "a\r\nb\tc"] {
            let value = encrypt(PUBLIC_KEY, plaintext, true).unwrap();
            assert_eq!(decrypt(PRIVATE_KEY, &value, true).unwrap(), plaintext);
        }
    }

    #[test]
    fn large_value_round_trips() {
        let plaintext = "x".repeat(10240);
        let value = encrypt(PUBLIC_KEY, &plaintext, true).unwrap();
        assert_eq!(decrypt(PRIVATE_KEY, &value, true).unwrap(), plaintext);
    }

    // decrypt_with_key matches decrypt() once the key is parsed.
    #[test]
    fn decrypt_with_parsed_key_round_trips() {
        let secret = parse_private_key(PRIVATE_KEY).unwrap();
        assert_eq!(
            decrypt_with_key(&secret, GOLDEN_EXPANDED, true).unwrap(),
            "expanded"
        );
        let bare = encrypt(PUBLIC_KEY, "device", false).unwrap();
        assert_eq!(decrypt_with_key(&secret, &bare, false).unwrap(), "device");
    }
}

// Node Buffer decoding semantics the wire contract depends on. Checked against
// Node v26 `Buffer.from(str, 'base64'|'hex')` on 2026-07-11.
mod node_decoders {
    use super::*;

    #[test]
    fn base64_lenient_decode_matches_node() {
        let cases: &[(&str, &str)] = &[
            ("aGVsbG8=", "68656c6c6f"),
            ("aGV!sbG8=", "68656c6c6f"),     // invalid chars skipped
            ("aGVsbG8=extra", "68656c6c6f"), // '=' terminates decoding
            ("aGVsbG8", "68656c6c6f"),       // missing padding tolerated
            ("a", ""),                       // lone char dropped
            ("ab", "69"),                    // 2 chars -> 1 byte
            ("abc", "69b7"),                 // 3 chars -> 2 bytes
            ("!!!not-base64!!!", "9e8b7e6dab1eeb"), // url-alphabet '-' accepted
            ("aG=VsbG8", "68"),
            ("aGVs bG8=", "68656c6c6f"), // whitespace skipped
            ("===", ""),
            ("aGVsbG8===", "68656c6c6f"),
            ("aGVsbG8-", "68656c6c6f3e"), // '-' = 62 (base64url)
            ("aGVsbG8_", "68656c6c6f3f"), // '_' = 63 (base64url)
        ];
        for &(input, expected_hex) in cases {
            let got = node_base64_decode(input)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            assert_eq!(got, expected_hex, "base64 decode of {input:?}");
        }
    }

    #[test]
    fn hex_lenient_decode_matches_node() {
        let cases: &[(&str, &str)] = &[
            ("deadbeef", "deadbeef"),
            ("deadbeefg", "deadbeef"), // trailing garbage stops decode
            ("deadbeefgg", "deadbeef"),
            ("dea", "de"),            // odd trailing nibble dropped
            ("xdeadbeef", ""),        // invalid first pair -> empty
            ("deadbe ef", "deadbe"),  // stops at invalid pair
            ("DEADBEEF", "deadbeef"), // case-insensitive
            ("deAdBeEf", "deadbeef"),
            ("de-adbeef", "de"),
        ];
        for &(input, expected_hex) in cases {
            let got = node_hex_decode(input)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            assert_eq!(got, expected_hex, "hex decode of {input:?}");
        }
    }

    #[test]
    fn base64_encode_is_standard_padded() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"h", "aA=="),
            (b"he", "aGU="),
            (b"hel", "aGVs"),
            (b"hello", "aGVsbG8="),
            (&[0xfb, 0xff, 0xfe], "+//+"),
        ];
        for &(input, expected) in cases {
            assert_eq!(base64_encode(input), expected, "encode {input:?}");
        }
    }
}

mod error_shape {
    use super::*;

    #[test]
    fn primitive_message_strips_code_prefix() {
        let e = CryptoError::coded(
            CryptoErrorCode::DecryptionFailed,
            "second arg must be public key",
        );
        assert_eq!(e.primitive_message(), "second arg must be public key");
        let raw = CryptoError::raw("Invalid private key");
        assert_eq!(raw.primitive_message(), "Invalid private key");
        // non-code bracket prefixes are NOT stripped (regex is ^\[[A-Z_]+\] ).
        let odd = CryptoError::raw("[not a code] hello");
        assert_eq!(odd.primitive_message(), "[not a code] hello");
    }
}

// -- property tests (proptest) ---------------------------------------------
//
// The v1 ECIES read path is an untrusted-input boundary (`encrypted:` values
// from a .env file) fuzzed by `ecies_decrypt`. These express the same contract
// as shrinking properties: the Node-parity codecs are total and round-trip,
// and `decrypt` never panics on arbitrary input against a fixed key.
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arb_string() -> impl Strategy<Value = String> {
        proptest::collection::vec(any::<char>(), 0..256).prop_map(|v| v.into_iter().collect())
    }

    proptest! {
      /// The standard-padded encoder round-trips through Node's lenient decoder:
      /// `node_base64_decode(base64_encode(x)) == x`.
      #[test]
      fn base64_round_trips(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        prop_assert_eq!(node_base64_decode(&base64_encode(&bytes)), bytes);
      }

      /// `node_base64_decode` is total on arbitrary strings (lenient: skips
      /// junk, stops at `=`), never a panic.
      #[test]
      fn node_base64_decode_never_panics(s in arb_string()) {
        let _ = node_base64_decode(&s);
      }

      /// `node_hex_decode` and `strict_hex_decode` are total on arbitrary input.
      #[test]
      fn hex_decoders_never_panic(s in arb_string()) {
        let _ = node_hex_decode(&s);
        let _ = strict_hex_decode(&s);
      }

      /// `decrypt` never panics on an arbitrary `encrypted:`-framed value against
      /// the fixed golden key — every malformed payload is a coded `Err`.
      #[test]
      fn decrypt_never_panics(s in arb_string()) {
        let _ = decrypt(PRIVATE_KEY, &s, true);
        let _ = decrypt(PRIVATE_KEY, &format!("{ENCRYPTED_PREFIX}{s}"), true);
        let _ = decrypt_key_value("KEY", &s, "ENVRYPT_PRIVATE_KEY", Some(PRIVATE_KEY));
      }

      /// ECIES round-trip identity: `decrypt(encrypt(pt)) == pt` for arbitrary
      /// UTF-8 plaintext against a freshly generated keypair.
      #[test]
      fn ecies_round_trip_is_identity(plaintext in arb_string()) {
        let kp = keypair();
        let value = encrypt(&kp.public_key, &plaintext, true).expect("encrypt");
        prop_assert_eq!(decrypt(&kp.private_key, &value, true), Ok(plaintext));
      }
    }
}
