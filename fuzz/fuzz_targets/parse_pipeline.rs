#![no_main]
//! FUZZ target `parse_pipeline` (WP-21, doc 11 §7.2 target 1).
//!
//! Raw bytes → the full file-ingestion path: encoding detection (UTF-16LE BOM
//! sniff / utf8 / latin1 fallback — spec case `902_UTF16LE` proves the honest
//! surface is raw bytes, NOT pre-validated UTF-8) → Node-parity decode to a
//! `String` → scan → expand. The pipeline spawns no child process at all, so
//! fuzz-derived bytes can never reach a shell.
//!
//! Finding = panic / abort / overflow / OOM / hang. A graceful `Err` is a
//! non-finding: `parse_with_ring` reports an expansion that outgrew its byte
//! budget through `ParseOutput::errors` rather than allocating without bound.
//!
//! Built via cargo-fuzz, which sets `--cfg fuzzing` and thereby lowers the
//! expansion iteration cap and byte budget so every exec stays fast.

#[cfg(not(fuzzing))]
compile_error!(
    "parse_pipeline must be built via cargo-fuzz (which sets --cfg fuzzing) so the \
     expansion caps are lowered to fuzz-sized budgets"
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
