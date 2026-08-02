//! Library-level conformance runner.
//!
//! Executes the parse-focused slice of the `conformance/` corpus against envrypt's
//! library parse pipeline, entirely in-process. The tier-1 corpus is the 88 spec cases
//! in `conformance/cases/spec/spec.json`, asserted as insertion-ordered parsed-map
//! equality: key order is contract.
//!
//! The parsed map comes from [`MapSource::ParsesTo`], the `parses_to` hook over
//! envrypt's parse pipeline, implemented by the in-repo `parser_conformance.rs`
//! harness.
//!
//! Every case runs in a fresh temp dir with the standard base environment plus
//! per-case `env:` preconditions. The base env is supplied per case via
//! [`run::BaseEnvFn`]: the in-repo harnesses pass `test_support::standard_env()`
//! through it, which keeps `test-support` a dev-dependency.
//!
//! Crypto and interop coverage lives in `crates/envrypt/tests`
//! (`interop_corpus.rs`, `crypto_vectors.rs`), driven by checked-in vectors.

pub mod case;
pub mod fixture;
pub mod normalize;
pub mod run;

pub use case::{load_spec_cases, spec_cases_path, Encoding, SpecCase};
pub use fixture::write_env_fixture;
pub use normalize::Mask;
pub use run::{
    run_spec_case, run_spec_suite, BaseEnv, BaseEnvFn, CaseFailure, MapSource, ParsesTo,
};
