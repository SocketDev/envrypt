//! The full .env parse pipeline: scan → process-env precedence → decrypt (ring)
//! → expand (with `\$` unescape) → parsed/injected/existed/errors bookkeeping.
//!
//! The pipeline spawns no child process: a `$(…)` sequence is ordinary text that
//! flows through untouched, since neither expansion regex matches a `$` followed
//! by `(`. This is a deliberate divergence from dotenvx, which shells out; see
//! `conformance/README.md`.
//!
//! [`parse_with_ring`] is the core synchronous pipeline over a prebuilt keyring;
//! [`public_key_hexes`] seeds that ring and orders decrypt attempts.

pub mod expand;
pub mod scan;

pub use expand::{expand, ExpandError, ExpandOptions};
pub use scan::{scan, scan_with, Quote, ScanEntry, ScanOptions};

use indexmap::IndexMap;
use std::borrow::Cow;

/// Unescapes `\$` to `$`. Parse applies this to the expand result so an escaped
/// dollar survives expansion as a literal `$`.
pub fn resolve_escape_sequences(value: &str) -> Cow<'_, str> {
    // Nothing to unescape without the two-byte `\$` sequence, so borrow the input.
    if memchr::memmem::find(value.as_bytes(), b"\\$").is_none() {
        return Cow::Borrowed(value);
    }
    Cow::Owned(value.replace("\\$", "$"))
}

/// Scans `src` and, for every public-key name (in first-appearance order), takes
/// that name's last value. Seeds the ring and orders decrypt attempts. Uses the
/// default `ENVRYPT_PUBLIC_KEY` naming; [`public_key_hexes_with`] takes an
/// explicit [`KeyNaming`].
pub fn public_key_hexes(src: &str) -> Vec<String> {
    public_key_hexes_with(src, crate::conventions::keynames::default_key_naming())
}

/// [`public_key_hexes`] under an explicit [`KeyNaming`] (the configurable
/// key-resolution path).
pub fn public_key_hexes_with(
    src: &str,
    naming: &crate::conventions::keynames::KeyNaming,
) -> Vec<String> {
    scan(src, &ScanOptions::default())
        .iter()
        .filter(|(name, _)| naming.is_public_key_name(name))
        .map(|(_, values)| values.last().cloned().unwrap_or_default())
        .collect()
}

/// Options for [`parse_with_ring`]. These are the parse-time knobs; the ring
/// itself is built before the call.
#[derive(Clone, Copy, Debug)]
pub struct ParseOptions<'a> {
    /// `overload` — parsed-so-far wins over processEnv.
    pub overload: bool,
    /// `array` — collect every occurrence per key instead of last-wins.
    pub array: bool,
    /// Include-key globs. These gate decryption only; the scan itself stays
    /// unfiltered.
    pub ik: &'a [String],
    /// Exclude-key globs. These gate decryption only.
    pub ek: &'a [String],
    /// The pre-existing process environment.
    pub process_env: &'a IndexMap<String, String>,
    /// The keyring: public-key hex → private-key hex (`""` marks an unfilled
    /// seed). Insertion order (seeds first, then discovery order) drives the
    /// try-every-other-key fallback in [`try_decrypt`].
    pub ring: &'a IndexMap<String, String>,
    /// The byte budget for one expanded value; exceeding it is an
    /// `EXPANSION_TOO_LARGE` error on that key.
    pub max_expand_output_bytes: usize,
    /// The key-identifier naming used to detect the in-file public-key header when
    /// seeding decrypt-attempt order (default `ENVRYPT_`).
    pub naming: &'a crate::conventions::keynames::KeyNaming,
}

impl<'a> ParseOptions<'a> {
    /// Defaults: no overload, no array, no filters, empty ring, the default
    /// expansion budget, default `ENVRYPT_` naming.
    pub fn new(process_env: &'a IndexMap<String, String>) -> Self {
        ParseOptions {
            overload: false,
            array: false,
            ik: &[],
            ek: &[],
            process_env,
            ring: empty_ring(),
            max_expand_output_bytes: expand::DEFAULT_MAX_EXPAND_OUTPUT_BYTES,
            naming: crate::conventions::keynames::default_key_naming(),
        }
    }
}

/// A shared empty ring for the common unencrypted path.
pub fn empty_ring() -> &'static IndexMap<String, String> {
    static EMPTY: std::sync::LazyLock<IndexMap<String, String>> =
        std::sync::LazyLock::new(IndexMap::new);
    &EMPTY
}

/// The single aggregated parse error, produced only when a value fails to
/// decrypt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub code: &'static str,
    pub message: String,
}

/// The parse result: `parsed`, `injected`, `existed`, and `errors`.
///
/// All maps are insertion-ordered; key order is part of the contract. Values are
/// `Vec<String>` to serve both modes: non-array mode keeps one element per key (a
/// later duplicate overwrites it in place), array mode pushes every occurrence in
/// file order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParseOutput {
    pub parsed: IndexMap<String, Vec<String>>,
    pub injected: IndexMap<String, Vec<String>>,
    pub existed: IndexMap<String, Vec<String>>,
    pub errors: Vec<ParseError>,
}

impl ParseOutput {
    /// Flattens `parsed` to one value per key (last wins), in insertion order.
    /// This is the effective map the conformance corpus asserts.
    pub fn parsed_map(&self) -> IndexMap<String, String> {
        self.parsed
            .iter()
            .map(|(k, v)| (k.clone(), v.last().cloned().unwrap_or_default()))
            .collect()
    }
}

/// The core parse pipeline over a prebuilt ring.
pub fn parse_with_ring(src: &str, opts: &ParseOptions) -> ParseOutput {
    let public_keys = public_key_hexes_with(src, opts.naming);
    let process_env = opts.process_env;

    // Build the ik/ek matcher pair once per call. An invalid pattern panics here;
    // callers that accept user-supplied globs pre-validate via `edit::KeyFilter`.
    let key_filter =
        crate::edit::KeyFilter::new(opts.ik, opts.ek).unwrap_or_else(|e| panic!("{e}"));
    let ik_skips = |name: &str| -> bool { key_filter.skips(name) };

    let mut running_parsed: IndexMap<String, String> = IndexMap::new();
    let mut literals: IndexMap<String, String> = IndexMap::new();
    let mut parsed: IndexMap<String, Vec<String>> = IndexMap::new();
    let mut injected: IndexMap<String, Vec<String>> = IndexMap::new();
    let mut existed: IndexMap<String, Vec<String>> = IndexMap::new();
    // Failed-decryption set: unique names in first-failure order.
    let mut failed: Vec<String> = Vec::new();
    // Expansion budget overruns, in encounter order. Each is its own error: the
    // key names the value whose expansion could not fit.
    let mut errors: Vec<ParseError> = Vec::new();

    // Scan runs unfiltered; the ik/ek matchers gate decryption only.
    scan_with(src, &ScanOptions::default(), |entry| {
        let name = entry.name;
        let quote = entry.quote;
        let mut k = entry.value.to_string();
        let has_own = process_env.contains_key(name);

        // Process-env precedence: a key already present in the environment wins,
        // unless `overload` flips it.
        if !opts.overload && has_own {
            k = process_env[name].clone();
        }

        let was_encrypted = crate::crypto::is_encrypted(&k);

        // Decrypt, gated by ik/ek (skip when the filters exclude the name).
        if !ik_skips(name) {
            k = try_decrypt(opts.ring, &k, &public_keys, name);
            if was_encrypted && crate::crypto::is_encrypted(&k) && !failed.iter().any(|f| f == name)
            {
                failed.push(name.to_string());
            }
        }

        let still_encrypted = crate::crypto::is_encrypted(&k);

        // Expansion. Its gate tests TRUTHINESS (`!processEnv[name] || overload`),
        // where the precedence gate above tests key PRESENCE — an empty
        // pre-existing value wins there and still flows through expand here. A
        // budget overrun records an error and leaves the unexpanded value in place,
        // so a caller never receives a truncated one.
        let truthy_process_env = process_env.get(name).is_some_and(|v| !v.is_empty());
        if !still_encrypted && quote != Quote::Single && (!truthy_process_env || opts.overload) {
            match expand(
                &k,
                &ExpandOptions {
                    overload: opts.overload,
                    process_env,
                    running_parsed: &running_parsed,
                    literals: &literals,
                    max_output_bytes: opts.max_expand_output_bytes,
                },
            ) {
                Ok(expanded) => {
                    let resolved_owned = match resolve_escape_sequences(&expanded) {
                        Cow::Borrowed(_) => None,
                        Cow::Owned(resolved) => Some(resolved),
                    };
                    k = resolved_owned.unwrap_or(expanded);
                }
                Err(e) => errors.push(ParseError {
                    code: "EXPANSION_TOO_LARGE",
                    message: crate::errors::EnvryptError::expansion_too_large(
                        name,
                        e.max_output_bytes,
                    )
                    .message()
                    .to_string(),
                }),
            }
        }

        // Record single-quoted literals; expand's literals-guard reads them.
        if quote == Quote::Single {
            literals.insert(name.to_string(), k.clone());
        }

        // runningParsed feeds later lines' expansions.
        running_parsed.insert(name.to_string(), k.clone());

        // Array mode pushes each occurrence; non-array overwrites in place, keeping
        // the key's original position.
        if opts.array {
            parsed.entry(name.to_string()).or_default().push(k.clone());
        } else {
            let slot = parsed.entry(name.to_string()).or_default();
            slot.clear();
            slot.push(k.clone());
        }

        // injected/existed bookkeeping.
        if has_own && !opts.overload {
            let process_value = process_env[name].clone();
            if opts.array {
                existed
                    .entry(name.to_string())
                    .or_default()
                    .push(process_value);
            } else {
                let slot = existed.entry(name.to_string()).or_default();
                slot.clear();
                slot.push(process_value);
            }
        } else if opts.array {
            injected
                .entry(name.to_string())
                .or_default()
                .push(k.clone());
        } else {
            // Inject the current parsed value.
            let slot = injected.entry(name.to_string()).or_default();
            slot.clear();
            slot.push(k.clone());
        }

        k
    });

    // Exactly one aggregated error when any key failed decryption.
    if !failed.is_empty() {
        errors.push(ParseError {
            code: "DECRYPTION_FAILED",
            message: format!(
                "[DECRYPTION_FAILED] could not decrypt {}",
                failed.join(", ")
            ),
        });
    }

    ParseOutput {
        parsed,
        injected,
        existed,
        errors,
    }
}

/// Tries every candidate private key against `value` and returns the first
/// success, or `value` unchanged when all fail. Order: the keys named by
/// `public_key_hexes` first, then every other non-empty ring key in insertion
/// order. Each attempt routes on the payload version byte
/// (`crypto_v3::decrypt_entry`): a `0x03` payload takes the v3 path bound to
/// `name`; everything else takes the v1 path, which ignores the name and returns
/// non-`encrypted:` values untouched (so a plain value "succeeds" on the first
/// available key).
fn try_decrypt(
    ring: &IndexMap<String, String>,
    value: &str,
    public_key_hexes: &[String],
    name: &str,
) -> String {
    let mut tried: Vec<&str> = Vec::new();
    for public_key in public_key_hexes {
        let Some(private_key) = ring.get(public_key) else {
            continue;
        };
        if private_key.is_empty() {
            continue;
        }
        tried.push(private_key);
        if let Ok(decrypted) = crate::crypto_v3::decrypt_entry(private_key, value, name) {
            return decrypted;
        }
    }
    for private_key in ring.values() {
        if private_key.is_empty() || tried.iter().any(|t| t == private_key) {
            continue;
        }
        if let Ok(decrypted) = crate::crypto_v3::decrypt_entry(private_key, value, name) {
            return decrypted;
        }
    }
    value.to_string()
}

#[cfg(test)]
mod config_expand_test;
#[cfg(test)]
mod parse_multiline_test;
#[cfg(test)]
mod parse_test;
#[cfg(test)]
mod pipeline_tests;
#[cfg(test)]
mod test_helpers;
