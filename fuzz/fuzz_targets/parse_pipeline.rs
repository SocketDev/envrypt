#![no_main]
//! FUZZ target `parse_pipeline` (WP-21, doc 11 §7.2 target 1).
//!
//! Raw bytes → the full file-ingestion path: encoding detection (UTF-16LE BOM
//! sniff / utf8 / latin1 fallback — spec case `902_UTF16LE` proves the honest
//! surface is raw bytes, NOT pre-validated UTF-8) → Node-parity decode to a
//! `String` → scan → expand → the evaluate gate. Command substitution `$()` is
//! stubbed to a deterministic pure function inside `parse::evaluate` (active
//! because cargo-fuzz sets `--cfg fuzzing`) so fuzz-derived bytes are NEVER
//! executed by a shell, while the real `EVAL_RE` match + `$`-pattern replacement
//! is still exercised.
//!
//! Finding = panic / abort / overflow / OOM / hang. `Err` returns from the parse
//! pipeline (there are none at this entry — `parse_with_ring` is infallible with
//! an empty ik/ek `KeyFilter`) and truncated-but-panic-free output on the D-05
//! non-termination guards are graceful non-findings.
//!
//! SAFETY: this target relies on `--cfg fuzzing` neutralizing `$()`. The
//! `compile_error!` below makes a non-fuzzing build fail loudly rather than
//! silently spawn shells on fuzz bytes.

#[cfg(not(fuzzing))]
compile_error!(
    "parse_pipeline must be built via cargo-fuzz (which sets --cfg fuzzing) so that \
     command substitution `$()` is stubbed; never run this target without --cfg fuzzing"
);

use envrypt::{fsio, parse};
use indexmap::IndexMap;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Encoding detection over RAW bytes, then Node-parity decode — byte-identical
    // to the CLI's `detect_encoding` + `read_file_x` on a .env file, minus the
    // filesystem read (doc 11 §7.2 target 1).
    let encoding = fsio::detect_encoding_bytes(data);
    let src = fsio::decode(data, encoding);

    // Full parse pipeline: empty process env + empty ring (crypto is fuzzed by
    // `ecies_decrypt`, not here — an empty ring never attempts decryption).
    // Empty ik/ek => the internal `KeyFilter` is infallible, so `parse_with_ring`
    // cannot panic on pattern validation.
    let process_env: IndexMap<String, String> = IndexMap::new();
    let out = parse::parse_with_ring(&src, &parse::ParseOptions::new(&process_env));
    std::hint::black_box(out);
});
