# Conformance corpus

The conformance corpus checks that envrypt's parser and crypto match a fixed,
checked-in spec. Every case lives in this directory, so the suite is
self-contained: it runs no external tool and never skips.

```
conformance/
  cases/
    spec/spec.json        The tier-1 parse spec — one case per grammar rule,
                          each an input string and the map it must parse to.
                          `runner/tests/tier1_spec.rs` checks the corpus shape.
    parser/encoding.json  utf16le / latin1 fixtures: the input bytes must
                          re-parse to the checked-in map.
    expand.yaml           Reference examples of `${VAR}` expansion, kept as
                          documentation.
  fixtures/               Byte-exact `.env` fixtures. `.gitattributes` marks
                          them `-text` so CRLF and BOMs stay intact, and a
                          `.gitignore` negation keeps the repo's `.env*` rule
                          from swallowing them. Read by
                          `runner/tests/parser_conformance.rs`.
  vectors/
    crypto.json           Golden crypto vectors: encrypted values plus their
                          plaintext, and the malformed inputs that must error.
                          Read by `crates/envrypt/tests/crypto_vectors.rs`.
    interop/interop.json  The wire-format freeze corpus — one vector set per
                          supported `encrypted:` / `locked:` layout (v1 and v3),
                          all minted in-repo. Read by
                          `crates/envrypt/tests/interop_corpus.rs`.
  runner/                 The `envrypt-conformance` crate (workspace member,
                          never published): a JSON case loader, a fixture
                          writer, and a `parses_to` executor that drives cases
                          through envrypt's parse pipeline.
```

## Deliberate divergences from dotenvx

The corpus is inherited from dotenvx, so a case whose golden value differs on
purpose carries a `notes` field beginning `DIVERGENCE from dotenvx:`. Grep for
that prefix to see the full list.

- **`$(…)` command substitution is literal text** (cases `504`, `505`, `506`,
  `601`). dotenvx shells each `$(…)` out through `execSync`. envrypt spawns no
  child process while parsing, so a `.env` that an attacker can write cannot
  reach a shell. The parens and the command word survive verbatim; an inner
  `$VAR` still expands, because `$(` matches neither expansion alternative.

## Running it

```
cargo test -p envrypt-conformance
```

`tier1_spec.rs` checks the corpus shape; `parser_conformance.rs` runs every
tier-1 case and the encoding fixtures through envrypt's parser and compares the
parsed map, key order included. The crypto vectors and the interop tripwire run
in the main suite (`cargo test --workspace`).

## Regenerating the interop vectors

```
cargo test -p envrypt --test interop_corpus regenerate_interop_corpus -- --ignored
```

This mints a fresh set of `encrypted:` / `locked:` vectors (v1 and v3) from
envrypt's own writers and rewrites `interop/interop.json`. The tripwire then
proves envrypt keeps decrypting every supported layout.
