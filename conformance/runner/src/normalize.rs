//! Mechanical output normalization. Every rule is a deterministic filter, never a
//! hand-tuned per-case patch.

use regex::Regex;
use std::sync::OnceLock;

/// Randomized-crypto masks beyond the always-on default pipeline. Masks exist so
/// content that embeds randomized crypto material (fresh keypairs, ciphertext) stays
/// diffable: ciphertext is never byte-compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mask {
    /// `0[23]` + 64 hex chars (compressed secp256k1 public key) → `PUBLIC_KEY`.
    PublicKey,
    /// 64 hex chars → `PRIVATE_KEY` (applied after [`Mask::PublicKey`]).
    PrivateKey,
    /// `encrypted:<base64>` → `encrypted:CIPHERTEXT`.
    Ciphertext,
}

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static normalizer regex compiles"))
}

/// Strip ANSI SGR escapes. The standard test env yields color depth 1 so none should
/// appear; this is belt-and-braces.
pub fn strip_ansi(s: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, "\u{1b}\\[[0-9;]*m").replace_all(s, "").into_owned()
}

/// Drop Node runtime warning lines (`(node:PID) Warning: …`, whose PID makes even
/// repeat runs diverge) plus Node's standard ``(Use `node --trace-warnings ...` …)``
/// follow-up line.
pub fn strip_node_warnings(s: &str) -> String {
    drop_lines(s, |line| {
        static WARN: OnceLock<Regex> = OnceLock::new();
        static TRACE: OnceLock<Regex> = OnceLock::new();
        re(&WARN, r"^\(node:\d+\) (\[[A-Z0-9]+\] )?\w*Warning: ").is_match(line)
            || re(&TRACE, r"^\(Use `node --trace-warnings").is_match(line)
    })
}

/// Drop armor status debug lines: the `┆ armor: on|off` logger.debug form.
pub fn strip_armor_status(s: &str) -> String {
    drop_lines(s, |line| {
        static CURRENT: OnceLock<Regex> = OnceLock::new();
        re(&CURRENT, r"^(┆ )?armor: (on|off)$").is_match(line)
    })
}

/// Drop the `"armor":<bool>` key from the `┆ options:` debug JSON so options-JSON
/// comparisons ignore it. The `"armor":true,` fragment is always immediately followed
/// by `"native"`, so erasing it leaves a well-formed object.
pub fn strip_armor_option(s: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, r#""armor":(true|false),"#)
        .replace_all(s, "")
        .into_owned()
}

/// Drop any `⛨ ARMORED KEYS` comment line from a `.env.keys` banner so file
/// comparisons cover the banner and key content. The line is a comment; it never
/// affects parse or decrypt results. Applies to file bytes and streams.
pub fn strip_armored_keys_header(s: &str) -> String {
    drop_lines(s, |line| line.contains("ARMORED KEYS"))
}

/// Replace the case dir (raw and symlink-resolved forms, e.g. macOS `/var` vs
/// `/private/var`) with `${CWD}`.
pub fn mask_tmpdir(s: &str, cwd: &std::path::Path) -> String {
    let mut out = s.to_string();
    let canonical = cwd.canonicalize().ok();
    let raw = cwd.to_string_lossy().into_owned();
    // Longest first so `/private/var/...` never leaves a dangling `/private` behind.
    let mut needles: Vec<String> = Vec::new();
    if let Some(c) = canonical {
        needles.push(c.to_string_lossy().into_owned());
    }
    needles.push(raw);
    needles.sort_by_key(|n| std::cmp::Reverse(n.len()));
    needles.dedup();
    for needle in needles {
        if !needle.is_empty() {
            out = out.replace(&needle, "${CWD}");
        }
    }
    out
}

/// Apply one randomized-crypto mask: structural regexes for keys, and ciphertext is
/// never byte-compared. Masks keep spec expectations writable on cases with per-run
/// key material.
pub fn apply_mask(s: &str, mask: Mask) -> String {
    match mask {
        Mask::PublicKey => {
            static RE_PK: OnceLock<Regex> = OnceLock::new();
            re(&RE_PK, r"\b0[23][0-9a-f]{64}\b")
                .replace_all(s, "PUBLIC_KEY")
                .into_owned()
        }
        Mask::PrivateKey => {
            static RE_SK: OnceLock<Regex> = OnceLock::new();
            re(&RE_SK, r"\b[0-9a-f]{64}\b")
                .replace_all(s, "PRIVATE_KEY")
                .into_owned()
        }
        Mask::Ciphertext => {
            static RE_CT: OnceLock<Regex> = OnceLock::new();
            re(&RE_CT, r"encrypted:[A-Za-z0-9+/=]+")
                .replace_all(s, "encrypted:CIPHERTEXT")
                .into_owned()
        }
    }
}

/// The full stream pipeline: defaults (strip_ansi → strip_node_warnings →
/// strip_armor_status → strip_armor_option → mask_tmpdir) then the case's masks in
/// declaration order. `Mask::PublicKey` is ordered before `Mask::PrivateKey` by
/// construction in the corpus files (a 66-hex pubkey contains no word boundary, but
/// keep them ordered anyway for clarity).
pub fn normalize_stream(s: &str, cwd: &std::path::Path, masks: &[Mask]) -> String {
    let mut out = strip_armored_keys_header(&strip_armor_option(&strip_armor_status(
        &strip_node_warnings(&strip_ansi(s)),
    )));
    out = mask_tmpdir(&out, cwd);
    for &m in masks {
        out = apply_mask(&out, m);
    }
    out
}

/// File contents get the case's masks PLUS the `.env.keys` banner-line strip (the
/// `⛨ ARMORED KEYS` line is a comment — it never affects `parses_to`/`decrypts_to`,
/// only the raw byte diff). The stream-level line filters are deliberately NOT
/// applied here (file bytes are contract; they would hide real divergence).
pub fn normalize_file(s: &str, masks: &[Mask]) -> String {
    let mut out = strip_armored_keys_header(s);
    for &m in masks {
        out = apply_mask(&out, m);
    }
    out
}

/// Line-dropping helper that never invents or removes a trailing newline: it
/// operates on newline-terminated segments.
fn drop_lines(s: &str, mut pred: impl FnMut(&str) -> bool) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(idx) = rest.find('\n') {
        let (line, tail) = rest.split_at(idx + 1);
        if !pred(line.trim_end_matches(['\n', '\r'])) {
            out.push_str(line);
        }
        rest = tail;
    }
    if !rest.is_empty() && !pred(rest) {
        out.push_str(rest);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_ansi_removes_sgr_only() {
        assert_eq!(strip_ansi("\u{1b}[32mok\u{1b}[0m"), "ok");
        assert_eq!(strip_ansi("plain"), "plain");
    }

    #[test]
    fn node_warning_lines_are_dropped_with_their_trace_hint() {
        let s = "(node:123) Warning: The 'NO_COLOR' env is ignored\n(Use `node --trace-warnings ...` to show where the warning was created)\nreal\n";
        assert_eq!(strip_node_warnings(s), "real\n");
        // Deprecation-style variants too.
        let s = "(node:9) [DEP0040] DeprecationWarning: nope\nkeep\n";
        assert_eq!(strip_node_warnings(s), "keep\n");
    }

    #[test]
    fn armor_status_lines_are_dropped() {
        let s = "┆ armor: off\narmor: on\nHello\n";
        assert_eq!(strip_armor_status(s), "Hello\n");
        // Never drops a line merely containing the word.
        assert_eq!(strip_armor_status("armor: broken\n"), "armor: broken\n");
    }

    #[test]
    fn armor_option_field_is_erased_from_options_json() {
        // Erasing the field leaves a well-formed object (native immediately follows).
        assert_eq!(
      strip_armor_option(
        "┆ options: {\"env\":[],\"envFile\":[],\"strict\":false,\"armor\":true,\"native\":true}\n"
      ),
      "┆ options: {\"env\":[],\"envFile\":[],\"strict\":false,\"native\":true}\n"
    );
        // Output already lacking the armor field passes through unchanged.
        assert_eq!(
            strip_armor_option("┆ options: {\"strict\":false,\"native\":true}\n"),
            "┆ options: {\"strict\":false,\"native\":true}\n"
        );
    }

    #[test]
    fn mask_tmpdir_handles_raw_and_canonical_forms() {
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().to_string_lossy().into_owned();
        let canon = dir.path().canonicalize().unwrap();
        let s = format!(
            "loading env from .env ({raw}/.env)\ncanonical: {}/.env\n",
            canon.display()
        );
        let masked = mask_tmpdir(&s, dir.path());
        assert_eq!(
            masked,
            "loading env from .env (${CWD}/.env)\ncanonical: ${CWD}/.env\n"
        );
    }

    #[test]
    fn masks_replace_keys_and_ciphertext() {
        let pk = "03eaf2142ab3d55bdf108962334e06696db798e7412cfc51d75e74b4f87f299bba";
        let sk = "ec9e80073d7ace817d35acb8b7293cbf8e5981b4d2f5708ee5be405122993cd1";
        let s = format!("PUB={pk} PRIV={sk} V=encrypted:BG8M6U+ABC/123=");
        let masked = apply_mask(
            &apply_mask(&apply_mask(&s, Mask::PublicKey), Mask::PrivateKey),
            Mask::Ciphertext,
        );
        assert_eq!(
            masked,
            "PUB=PUBLIC_KEY PRIV=PRIVATE_KEY V=encrypted:CIPHERTEXT"
        );
    }

    #[test]
    fn drop_lines_preserves_absent_trailing_newline() {
        assert_eq!(drop_lines("a\nb", |l| l == "a"), "b");
        assert_eq!(drop_lines("a\nb\n", |l| l == "b"), "a\n");
    }
}
