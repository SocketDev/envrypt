#!/usr/bin/env python3
"""Regenerate the WP-21 fuzz seed corpus (doc 11 §7.3).

Seed corpus = the 88 tier-1 spec case inputs (conformance/cases/spec/spec.json)
+ the tap fixtures (conformance/fixtures/**) + a handful of crafted, per-target
edge seeds (placeholder-collision text, CR/CRLF, BOMs, short ECIES payloads).

Idempotent: rewrites fuzz/corpus/<target>/ from source. Seed files are named with
neutral prefixes (never `.env*`) so the repo's `.gitignore` does not skip them.
Run from anywhere: `python3 fuzz/seed-corpus.py`.

Two modes:
  * default (reset): each fuzz/corpus/<target>/ dir is wiped and rebuilt to EXACTLY
    the seed set — the committed corpus is deterministic (used by the PR/push smoke
    job, which starts from a clean checkout).
  * `--additive`: seed files are written ON TOP of whatever already exists in each
    corpus dir, without deleting anything. The nightly CI job restores its
    coverage-guided corpus from cache and then runs this in additive mode so the
    committed seeds are merged in WITHOUT clobbering fuzzer-discovered growth — that
    is how coverage accumulates across nights. Seed names never collide with
    libFuzzer's SHA1-hashed discovered inputs, so re-adding a seed is a no-op.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

FUZZ_DIR = Path(__file__).resolve().parent
REPO_ROOT = FUZZ_DIR.parent
SPEC = REPO_ROOT / "conformance" / "cases" / "spec" / "spec.json"
FIXTURES = REPO_ROOT / "conformance" / "fixtures"

TARGETS = (
    "crypto_v3_decrypt",
    "ecies_decrypt",
    "parse_pipeline",
    "sockeye_decode",
    "upsert_roundtrip",
)

UPSERT_PLACEHOLDER = b"\x00ENVRYPT_UPSERT_0\x00"
UTF16LE_BOM = b"\xff\xfe"


def flat_name(path: Path) -> str:
    rel = path.relative_to(FIXTURES).as_posix()
    return "fixture-" + re.sub(r"[^A-Za-z0-9]+", "_", rel).strip("_")


def write_seed(target: str, name: str, data: bytes) -> None:
    (FUZZ_DIR / "corpus" / target / name).write_bytes(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--additive",
        action="store_true",
        help="merge seeds into existing corpus dirs WITHOUT deleting discovered "
        "growth (nightly CI cached-corpus mode); default resets to the seed set",
    )
    args = parser.parse_args(argv)

    if not SPEC.is_file():
        print(f"missing spec corpus: {SPEC}", file=sys.stderr)
        return 1

    # Default: reset each corpus dir to EXACTLY the seed set — remove any
    # fuzzer-discovered growth so the committed corpus is deterministic.
    # `--additive`: keep whatever is already present (e.g. a cache-restored,
    # coverage-guided corpus) and only layer the seeds on top.
    for target in TARGETS:
        d = FUZZ_DIR / "corpus" / target
        if d.exists() and not args.additive:
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)

    # --- 88 tier-1 spec inputs -> parse_pipeline (raw .env bytes) ---
    cases = json.loads(SPEC.read_text(encoding="utf-8"))
    for case in cases:
        write_seed("parse_pipeline", f"spec-{case['id']}", case["input"].encode("utf-8"))

    # --- tap fixtures -> parse_pipeline + upsert_roundtrip (raw file bytes) ---
    fixture_bytes: list[bytes] = []
    for path in sorted(FIXTURES.rglob("*")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        fixture_bytes.append(data)
        name = flat_name(path)
        write_seed("parse_pipeline", name, data)
        write_seed("upsert_roundtrip", name, data)

    # --- encrypted: values (from every fixture) -> ecies_decrypt +
    # crypto_v3_decrypt (the v3 target calls decrypt_v3 on `encrypted:` values) ---
    enc_re = re.compile(rb"encrypted:[A-Za-z0-9+/=]+")
    seen: set[bytes] = set()
    idx = 0
    for data in fixture_bytes:
        for m in enc_re.findall(data):
            if m in seen:
                continue
            seen.add(m)
            # both the full `encrypted:` string and the bare base64 payload
            write_seed("ecies_decrypt", f"enc-{idx}", m)
            write_seed("ecies_decrypt", f"payload-{idx}", m[len(b"encrypted:") :])
            write_seed("crypto_v3_decrypt", f"enc-{idx}", m)
            idx += 1

    # --- locked: values (from every fixture) -> crypto_v3_decrypt (the v3 target
    # calls unlock_v3 on `locked:<pub>:<payload>` values) ---
    locked_re = re.compile(rb"locked:[A-Za-z0-9:+/=]+")
    seen_locked: set[bytes] = set()
    lidx = 0
    for data in fixture_bytes:
        for m in locked_re.findall(data):
            if m in seen_locked:
                continue
            seen_locked.add(m)
            write_seed("crypto_v3_decrypt", f"locked-{lidx}", m)
            lidx += 1

    # --- crafted edge seeds ---
    # parse_pipeline: encodings, command sub, expansion, escapes.
    craft_parse = {
        "craft-utf16le": UTF16LE_BOM + "HELLO=\"utf16le\"".encode("utf-16-le"),
        "craft-utf8bom": b"\xef\xbb\xbfA=1\n",
        "craft-cmdsub": b"A=$(echo hi)\nB=${A}-x\n",
        "craft-cmdsub-dollar": b"A=$(printf '$&')\n",
        "craft-expand-self": b"SET='${SET}'\nX=${SET}\n",
        # Regression seed for the MULTIPLICATIVE self-reinserting expand class.
        # SET carries a live `${SET}` (escaped, so expand leaves it and the parse
        # step un-escapes it) plus a `$'`, so expanding `${SET}${SET}` grows the
        # result exponentially per pass. Left unbounded this allocates gigabytes;
        # the `cfg(fuzzing)` output-size guard in parse::expand bounds it. This
        # input class does not terminate under the reference grammar either
        # (throws V8 Invalid-string-length, exit 1) — D-05, not a Rust bug.
        "craft-expand-multiplicative": b"SET=\\${SET}$'x\nX=${SET}${SET}\n",
        "craft-escaped": b"E=\\$ESCAPED\n",
        "craft-crlf": b"A=1\r\nB=2\r\n",
        "craft-cr-only": b"A=1\rB=2\r",
        "craft-encrypted-line": b"DOTENV_PUBLIC_KEY=abc\nS=\"encrypted:${X}\"\n",
    }
    for name, data in craft_parse.items():
        write_seed("parse_pipeline", name, data)

    # upsert_roundtrip: arbitrary consumes raw bytes; seed placeholder-collision,
    # CR/CRLF, BOM-prefixed key, blank-value-at-EOF shapes.
    craft_upsert = {
        "craft-placeholder": b"K=" + UPSERT_PLACEHOLDER + b"\nX=1\n",
        "craft-blank-eof": b"K=\n",
        "craft-blank-blankline": b"K=\n\n",
        "craft-crlf": b"K=old\r\nX=1\r\n",
        "craft-cr-only": b"K=old\rX=1\r",
        "craft-bom-key": UTF16LE_BOM + b"K=v\n",
        "craft-dupes": b"K=a\nMID=x\nK=b\n",
        "craft-quoted": b"K=\"quoted value\"\n",
        "craft-export": b"export K=old\n",
    }
    for name, data in craft_upsert.items():
        write_seed("upsert_roundtrip", name, data)

    # ecies_decrypt: raw byte planes — short payloads that never reach a full point.
    craft_ecies = {
        "craft-empty": b"",
        "craft-prefix-only": b"encrypted:",
        "craft-tiny": b"encrypted:1234",
        "craft-33bytes": bytes(range(33)),
        "craft-97bytes": bytes(97),
        "craft-plaintext": b"just some plaintext to round-trip",
    }
    for name, data in craft_ecies.items():
        write_seed("ecies_decrypt", name, data)

    # crypto_v3_decrypt: consumes UTF-8-lossy strings routed to decrypt_v3 /
    # unlock_v3 with and without the `encrypted:` / `locked:` prefixes, plus a
    # plaintext for the recipient round-trip path.
    craft_v3 = {
        "craft-empty": b"",
        "craft-encrypted-prefix": b"encrypted:",
        "craft-locked-prefix": b"locked:",
        "craft-tiny-encrypted": b"encrypted:AAAA",
        "craft-plaintext": b"round-trip me",
    }
    for name, data in craft_v3.items():
        write_seed("crypto_v3_decrypt", name, data)

    # sockeye_decode: consumes raw bytes routed to sockeye::decode. Seed the
    # binary record shape (EV1 header + u16-BE name/value lengths + name + value)
    # plus header-only / truncated edges.
    ev1_header = b"EV1\x01"

    def sockeye_record(field: bytes, value: bytes) -> bytes:
        return (
            ev1_header
            + len(field).to_bytes(2, "big")
            + len(value).to_bytes(2, "big")
            + field
            + value
        )

    craft_sockeye = {
        "craft-empty": b"",
        "craft-header-only": ev1_header,
        "craft-truncated": ev1_header + b"\x00\x04",
        "craft-record": sockeye_record(b"ENVRYPT_SECRET", b"0" * 64),
        "craft-record-short": sockeye_record(b"K", b"ab"),
    }
    for name, data in craft_sockeye.items():
        write_seed("sockeye_decode", name, data)

    label = "corpus files (seeds + kept growth)" if args.additive else "seed files"
    for target in TARGETS:
        n = sum(1 for _ in (FUZZ_DIR / "corpus" / target).iterdir())
        print(f"{target}: {n} {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
