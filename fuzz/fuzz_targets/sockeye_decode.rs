#![no_main]
//! FUZZ target `sockeye_decode` — the Sockeye `envrypt-v1` inherited-pipe parser.
//!
//! Raw fuzz bytes are fed straight into `sockeye::decode` as the wire record read
//! from the inherited descriptor (`&[u8]` is `Read`), covering the exact byte
//! validation the production `read_pipe` runs on the descriptor it takes
//! ownership of via `File::from_raw_fd(3)` (crates/envrypt/src/sockeye.rs). The
//! `unsafe` `from_raw_fd` is an OS handoff with no bytes of its own to fuzz; the
//! parser it feeds is the whole surface an untrusted parent controls, so that is
//! what this target drives — which is why `sockeye.rs:53` annotates this target.
//!
//! Finding = panic / abort / overflow / OOM / hang. Every malformed record must
//! fail closed with a graceful `Err` (bad header / lengths / name / non-hex key /
//! short read / trailing byte); a graceful `Err`/`Ok` is a non-finding.
//!
//! Two lanes over one buffer:
//! (a) arbitrary bytes → `decode` NEVER panics (the primary property);
//! (b) a well-formed record built from the fuzz bytes round-trips: `decode`
//!     returns exactly its 64-hex key.

use envrypt::sockeye;
use libfuzzer_sys::fuzz_target;

/// The frozen `envrypt-v1` record header (`crates/envrypt/src/sockeye.rs`).
const HEADER: [u8; 4] = [b'E', b'V', b'1', 1];
const HEX: &[u8; 16] = b"0123456789abcdef";

fuzz_target!(|data: &[u8]| {
    // Lane (a): decode NEVER panics on arbitrary bytes; failures are graceful Err.
    let _ = sockeye::decode(data);

    // Lane (b): a well-formed record round-trips to its 64-hex key. The value is
    // derived from the fuzz bytes so the accept path is exercised on every input.
    let mut value = [0_u8; 64];
    for (i, slot) in value.iter_mut().enumerate() {
        let nibble = usize::from(data.get(i).copied().unwrap_or(0) & 0x0f);
        *slot = HEX[nibble];
    }
    let name = sockeye::CREDENTIAL_NAME.as_bytes();
    let mut record = Vec::with_capacity(HEADER.len() + 4 + name.len() + value.len());
    record.extend_from_slice(&HEADER);
    record.extend_from_slice(&(name.len() as u16).to_be_bytes());
    record.extend_from_slice(&(value.len() as u16).to_be_bytes());
    record.extend_from_slice(name);
    record.extend_from_slice(&value);

    let decoded = sockeye::decode(&record[..]).expect("well-formed record must decode");
    assert_eq!(
        decoded.as_bytes(),
        &value[..],
        "decode must return the record's 64-hex key"
    );
});
