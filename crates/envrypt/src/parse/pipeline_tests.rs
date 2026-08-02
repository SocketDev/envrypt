// Pins the per-entry transform order, the step gates, and the end-to-end
// output shapes, including encrypted values.
use super::test_helpers::*;
use super::*;

fn entries(map: &IndexMap<String, Vec<String>>) -> Vec<(String, Vec<String>)> {
    map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

fn one(pairs: &[(&str, &str)]) -> Vec<(String, Vec<String>)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), vec![v.to_string()]))
        .collect()
}

#[test]
fn verified_end_to_end_shape_default() {
    let pe = env(&[("PRE", "exists")]);
    let out = parse_env("PRE=file\nNEW=fresh\nREF=${PRE}-x", &pe);
    assert_eq!(
        entries(&out.parsed),
        one(&[("PRE", "exists"), ("NEW", "fresh"), ("REF", "exists-x")])
    );
    assert_eq!(
        entries(&out.injected),
        one(&[("NEW", "fresh"), ("REF", "exists-x")])
    );
    assert_eq!(entries(&out.existed), one(&[("PRE", "exists")]));
    assert!(out.errors.is_empty());
}

#[test]
fn verified_end_to_end_shape_overload() {
    let pe = env(&[("PRE", "exists")]);
    let mut opts = ParseOptions::new(&pe);
    opts.overload = true;
    let out = parse_with_ring("PRE=file\nREF=${PRE}-x", &opts);
    assert_eq!(
        entries(&out.parsed),
        one(&[("PRE", "file"), ("REF", "file-x")])
    );
    assert_eq!(
        entries(&out.injected),
        one(&[("PRE", "file"), ("REF", "file-x")])
    );
    assert!(out.existed.is_empty());
    assert!(out.errors.is_empty());
}

#[test]
fn verified_end_to_end_shape_array() {
    let pe = env(&[]);
    let mut opts = ParseOptions::new(&pe);
    opts.array = true;
    let out = parse_with_ring("L=one\nL=two", &opts);
    assert_eq!(
        entries(&out.parsed),
        vec![("L".to_string(), vec!["one".to_string(), "two".to_string()])]
    );
    assert_eq!(
        entries(&out.injected),
        vec![("L".to_string(), vec!["one".to_string(), "two".to_string()])]
    );
    assert!(out.existed.is_empty());
}

#[test]
fn duplicates_last_wins_keeps_original_position() {
    // A duplicate overwrites, keeping the key's original position.
    let out = parse_env("L=one\nMID=x\nL=two", &env(&[]));
    assert_eq!(entries(&out.parsed), one(&[("L", "two"), ("MID", "x")]));
}

/// `$(…)` is ordinary text. The parse pipeline runs no command, so a `.env` that
/// an attacker can write cannot reach a shell; a deliberate divergence from
/// dotenvx, recorded in `conformance/README.md`.
mod command_substitution_is_literal_text {
    use super::*;

    #[test]
    fn a_command_substitution_survives_as_literal_text() {
        // Bare, double-quoted, and single-quoted alike; a command that would have
        // failed is no more special than one that would have succeeded.
        for (src, expected) in [
            ("CMD=$(echo hi)", "$(echo hi)"),
            ("CMD=\"$(echo hi)\"", "$(echo hi)"),
            ("CMD='$(echo hi)'", "$(echo hi)"),
            ("CMD=$(exit 3)", "$(exit 3)"),
            ("CMD=pre $(echo hi) post", "pre $(echo hi) post"),
        ] {
            let out = parse_env(src, &env(&[]));
            assert_eq!(value(&out, "CMD"), expected, "source: {src}");
            assert!(out.errors.is_empty(), "source: {src}");
        }
    }

    #[test]
    fn a_preexisting_process_env_value_still_wins() {
        let out = parse_env("CMD=$(echo hi)", &env(&[("CMD", "other")]));
        assert_eq!(value(&out, "CMD"), "other");
        assert_eq!(out.existed.get("CMD").unwrap().last().unwrap(), "other");
    }

    #[test]
    fn an_inner_variable_reference_still_expands() {
        // `$(` matches neither expansion alternative, so the parens and the command
        // text pass through while an inner `$NAME` expands as usual.
        let out = parse_env("A=one\nB=$(echo $A)", &env(&[]));
        assert_eq!(value(&out, "A"), "one");
        assert_eq!(value(&out, "B"), "$(echo one)");
    }

    /// The direct observation: a `.env` whose value would run `touch` leaves no
    /// file behind, because nothing is executed. An assertion on the parsed string
    /// alone could pass while a child still ran.
    #[test]
    #[cfg(unix)]
    fn no_child_process_runs() {
        let dir = tempfile::tempdir().expect("temp dir");
        let marker = dir.path().join("spawned");
        let src = format!(
            "CMD=$(touch {0})\nQUOTED=\"$(/bin/sh -c 'touch {0}')\"\n",
            marker.display()
        );

        let out = parse_env(&src, &env(&[]));

        assert!(
            !marker.exists(),
            "parsing a `$(…)` value must spawn no child process"
        );
        assert_eq!(value(&out, "CMD"), format!("$(touch {})", marker.display()));
        assert_eq!(
            value(&out, "QUOTED"),
            format!("$(/bin/sh -c 'touch {}')", marker.display())
        );
    }
}

#[test]
fn escaped_dollar_is_unescaped_by_resolve_escape_sequences() {
    // The lookbehind blocks expansion of `\$ESCAPED`; resolveEscapeSequences
    // then unescapes it to `$ESCAPED`.
    let out = parse_env("E=\\$ESCAPED", &env(&[]));
    assert_eq!(value(&out, "E"), "$ESCAPED");
    // Single-quoted values reach neither expand nor resolveEscapeSequences.
    let out = parse_env("E='\\$KEEP'", &env(&[]));
    assert_eq!(value(&out, "E"), "\\$KEEP");
}

#[test]
fn empty_string_preexisting_value_still_expands_and_is_existed() {
    // Step 7's gate tests truthiness (`!processEnv[name]`), where steps 2 and
    // 6 test key presence. An empty pre-existing value wins at step 2 and
    // still flows through expand.
    let out = parse_env("PRE=${BASIC}-x\nBASIC=basic", &env(&[("PRE", "")]));
    assert_eq!(value(&out, "PRE"), "");
    assert_eq!(out.existed.get("PRE").unwrap().last().unwrap(), "");
    assert_eq!(value(&out, "BASIC"), "basic");
}

#[test]
fn resolve_escape_sequences_unit() {
    assert_eq!(resolve_escape_sequences(r"\$A and \$B"), "$A and $B");
    assert_eq!(resolve_escape_sequences("no dollars"), "no dollars");
}

#[test]
fn public_key_hexes_last_value_per_key_in_first_appearance_order() {
    // Last value per public-key name, in first-appearance order.
    let src = "ENVRYPT_PUBLIC_KEY=a\nENVRYPT_PUBLIC_KEY_PRODUCTION=b\nENVRYPT_PUBLIC_KEY=c";
    assert_eq!(
        public_key_hexes(src),
        vec!["c".to_string(), "b".to_string()]
    );
    assert!(public_key_hexes("HELLO=world").is_empty());
}

mod encrypted_values {
    // Decrypt happens inside the pipeline, then the plaintext is reprocessed.
    use super::*;
    use crate::crypto;

    fn ring_of(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn decrypted_plaintext_is_reprocessed_through_expand() {
        let kp = crypto::keypair();
        let secret = crypto::encrypt(&kp.public_key, "${BASE}-world", true).unwrap();
        // A decrypted `$(…)` is text like any other: reprocessing expands it, and
        // never executes it.
        let cmdsecret = crypto::encrypt(&kp.public_key, "$(echo dyn)", true).unwrap();
        let src = format!(
            "ENVRYPT_PUBLIC_KEY=\"{}\"\nBASE=hello\nSECRET=\"{}\"\nCMDSECRET=\"{}\"",
            kp.public_key, secret, cmdsecret
        );
        let pe = env(&[]);
        let ring = ring_of(&[(kp.public_key.as_str(), kp.private_key.as_str())]);
        let mut opts = ParseOptions::new(&pe);
        opts.ring = &ring;
        let out = parse_with_ring(&src, &opts);
        assert_eq!(value(&out, "SECRET"), "hello-world");
        assert_eq!(value(&out, "CMDSECRET"), "$(echo dyn)");
        assert!(out.errors.is_empty());
    }

    #[test]
    fn failed_decryption_keeps_ciphertext_and_aggregates_one_error() {
        let kp = crypto::keypair();
        let secret = crypto::encrypt(&kp.public_key, "plain", true).unwrap();
        let cmdsecret = crypto::encrypt(&kp.public_key, "other", true).unwrap();
        let src = format!(
            "ENVRYPT_PUBLIC_KEY=\"{}\"\nBASE=hello\nSECRET=\"{}\"\nCMDSECRET=\"{}\"",
            kp.public_key, secret, cmdsecret
        );
        let pe = env(&[]);
        // Ring seeded but unfilled ("") — decryption cannot succeed.
        let ring = ring_of(&[(kp.public_key.as_str(), "")]);
        let mut opts = ParseOptions::new(&pe);
        opts.ring = &ring;
        let out = parse_with_ring(&src, &opts);
        assert_eq!(value(&out, "SECRET"), secret.as_str());
        assert_eq!(value(&out, "CMDSECRET"), cmdsecret.as_str());
        assert_eq!(
            out.errors,
            vec![ParseError {
                code: "DECRYPTION_FAILED",
                message: "[DECRYPTION_FAILED] could not decrypt SECRET, CMDSECRET".to_string(),
            }]
        );
    }

    #[test]
    fn ek_excluded_keys_skip_decryption_without_error() {
        // The ik/ek matchers gate decryption only; an excluded key keeps its
        // ciphertext and is not recorded as a failure.
        let kp = crypto::keypair();
        let secret = crypto::encrypt(&kp.public_key, "sekret", true).unwrap();
        let other = crypto::encrypt(&kp.public_key, "плейн", true).unwrap();
        let src = format!(
            "ENVRYPT_PUBLIC_KEY=\"{}\"\nSECRET=\"{}\"\nOTHER=\"{}\"",
            kp.public_key, secret, other
        );
        let pe = env(&[]);
        let ring = ring_of(&[(kp.public_key.as_str(), kp.private_key.as_str())]);
        let ek = vec!["SECRET".to_string()];
        let mut opts = ParseOptions::new(&pe);
        opts.ring = &ring;
        opts.ek = &ek;
        let out = parse_with_ring(&src, &opts);
        assert_eq!(value(&out, "SECRET"), secret.as_str());
        assert_eq!(value(&out, "OTHER"), "плейн");
        assert!(out.errors.is_empty());
    }

    #[test]
    fn ring_fallback_tries_every_other_key_after_the_seeded_ones() {
        // try_decrypt uses the public-key-named keys first, then every
        // remaining ring key.
        let kp1 = crypto::keypair();
        let kp2 = crypto::keypair();
        let secret = crypto::encrypt(&kp2.public_key, "via-kp2", true).unwrap();
        let src = format!(
            "ENVRYPT_PUBLIC_KEY=\"{}\"\nSECRET=\"{}\"",
            kp1.public_key, secret
        );
        let pe = env(&[]);
        let ring = ring_of(&[
            (kp1.public_key.as_str(), kp1.private_key.as_str()),
            (kp2.public_key.as_str(), kp2.private_key.as_str()),
        ]);
        let mut opts = ParseOptions::new(&pe);
        opts.ring = &ring;
        let out = parse_with_ring(&src, &opts);
        assert_eq!(value(&out, "SECRET"), "via-kp2");
        assert!(out.errors.is_empty());
    }

    #[test]
    fn still_encrypted_values_skip_expand() {
        // While the `encrypted:` prefix remains, expansion is skipped.
        let src = "SECRET=\"encrypted:${NOT_EXPANDED}\"";
        let out = parse_env(src, &env(&[("NOT_EXPANDED", "boom")]));
        assert_eq!(value(&out, "SECRET"), "encrypted:${NOT_EXPANDED}");
        assert_eq!(
            out.errors[0].message,
            "[DECRYPTION_FAILED] could not decrypt SECRET"
        );
    }
}

#[test]
fn utf16le_decoded_bom_is_absorbed_by_the_line_regex() {
    // A decoded U+FEFF at position 0 counts as whitespace to the line regex,
    // so the key still parses.
    let out = parse_env("\u{FEFF}HELLO=utf16le", &env(&[]));
    assert_eq!(value(&out, "HELLO"), "utf16le");
}
