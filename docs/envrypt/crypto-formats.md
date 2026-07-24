# Legacy v1 crypto formats — read spec

envrypt reads two legacy encrypted-value layouts: the `encrypted:` v1 ECIES value
and the `locked:` v1 passphrase value. Both layouts are byte-frozen read formats:
values produced by the upstream reference implementation must keep decrypting under
envrypt, given the key. New values are written in the v3 format
(`docs/envrypt/crypto-v3.md`); the layouts below exist so existing files keep
working.

The bytes in this document are the contract. The interop tripwire
(`crates/envrypt/tests/interop_corpus.rs` over
`conformance/vectors/interop/interop.json`) decrypts a checked-in corpus of
legacy-produced values and must stay green; a red run is a stop-the-line bug, never
a golden to update.

See also: `docs/envrypt/crypto-v3.md` (the write format),
`conformance/vectors/crypto.json` (golden decrypt vectors + the frozen error
strings).

---

## 1. `encrypted:` v1 — ECIES value (`crates/envrypt/src/crypto.rs`)

The value form of an encrypted `.env` entry. ECIES (public-key encryption that
derives a fresh shared key per value) over secp256k1, HKDF-SHA256, AES-256-GCM
with a 16-byte nonce — a number used once per encryption.

### 1.1 String form

```
encrypted:<base64_std(payload)>
```

- `base64_std` is standard base64 (alphabet `A-Za-z0-9+/`, with `=` padding).
  Decoding is lenient the way Node's `Buffer.from(s, "base64")` is: invalid
  characters are skipped, so garbage after the prefix surfaces as a short or
  invalid payload rather than a decode error (`node_base64_decode` in
  `crypto.rs`).
- A value without the `encrypted:` prefix passes through decrypt unchanged as
  plaintext. The parse pipeline relies on this passthrough.
- A prefixless variant carries the same payload as bare base64 with the
  `encrypted:` prefix omitted (`prefix=false` in the low-level API). Same bytes,
  same rules.

### 1.2 Payload byte layout

```
offset  0                65               81               97
        +----------------+----------------+----------------+-----------------+
        | eph_pub  (65)  | nonce/iv (16)  | gcm tag  (16)  | ciphertext (N)  |
        +----------------+----------------+----------------+-----------------+
```

| field        | len | notes                                                                                            |
| ------------ | --- | ------------------------------------------------------------------------------------------------ |
| `eph_pub`    | 65  | SEC1 **uncompressed** secp256k1 point, leading byte `0x04`. A fresh ephemeral keypair per value. |
| `nonce`      | 16  | random AES-GCM nonce.                                                                            |
| `tag`        | 16  | AES-256-GCM auth tag, stored **before** the ciphertext.                                          |
| `ciphertext` | N   | AES-256-GCM ciphertext of the UTF-8 plaintext.                                                   |

Minimum payload length is `65+16+16 = 97` bytes.

### 1.3 Key schedule and AEAD

1. **ECDH:** `shared = recipient_pub · eph_priv`, serialized **uncompressed**
   (65 bytes).
2. **KDF:** `key = HKDF-SHA256(ikm = eph_pub(65) || shared(65), salt = ∅,
info = ∅, len = 32)`.
3. **AEAD:** AES-256-GCM with the 16-byte nonce and **empty AAD**. The cipher
   produces `ciphertext || tag`; the wire stores `tag || ciphertext`, so
   encode/decode reorder the two.
4. **Identity keys:** the private key is 64 hex chars (32 bytes); the public key
   stored in `.env` files is the **compressed** point (33 bytes, 66 hex chars).
   Only the ephemeral key inside the payload is uncompressed.

Frozen: the base64 variant, the field order, the 16-byte nonce, the empty AAD,
and the tag-before-ciphertext convention stay exactly as specified.

### 1.4 Decrypt failure → error taxonomy (frozen)

Decrypt failures map to one error code per failure condition. The conditions are
the contract (byte-level causes), and the emitted `code`/`message`/`help`/
`messageWithHelp` strings are pinned verbatim by `conformance/vectors/crypto.json`
`errors[]` and asserted by `crates/envrypt/tests/crypto_vectors.rs`.

| condition                                                                                        | code                       |
| ------------------------------------------------------------------------------------------------ | -------------------------- |
| private key absent or empty                                                                      | `MISSING_PRIVATE_KEY`      |
| private key fails secp256k1 scalar validation (bad hex, wrong length, zero, ≥ curve order)       | `INVALID_PRIVATE_KEY`      |
| AES-GCM tag mismatch (well-formed payload, wrong key)                                            | `WRONG_PRIVATE_KEY`        |
| leading 65 payload bytes fail secp256k1 point parse                                              | `MALFORMED_ENCRYPTED_DATA` |
| anything else (e.g. payload shorter than 97 bytes); the message embeds the underlying error text | `DECRYPTION_FAILED`        |

`INVALID_PRIVATE_KEY` and `WRONG_PRIVATE_KEY` share message text and differ only
in `code` and help URL. Each error carries `code`, `message`,
`help = "fix: [<url>]"`, and `messageWithHelp = "<message>. <help>"`
(`crates/envrypt/src/errors.rs`).

---

## 2. `locked:` v1 — passphrase-locked private key (`crates/envrypt/src/services/lock.rs`)

A private key encrypted at rest under a local passphrase. scrypt + AES-256-GCM
with a 12-byte IV. envrypt keeps the **unlock (read)** side of this layout.

### 2.1 String form

```
locked:<public_key_hex>:<base64url(payload)>
```

- `<public_key_hex>` is the compressed public-key hex the private key pairs
  with, echoed verbatim and unauthenticated in v1 (v3 binds its header into the
  AAD instead — see `crypto-v3.md`).
- `base64url` uses alphabet `A-Za-z0-9-_` with **no padding**.
- Parsing splits with `splitn(3, ':')`, so the payload segment is everything
  after the second `:`.

### 2.2 Payload byte layout

```
offset 0     1              17            29            45
       +-----+--------------+-------------+-------------+-----------------+
       | ver | salt (16)    | iv  (12)    | gcm tag(16) | ciphertext (N)  |
       | 0x01|              |             |             |                 |
       +-----+--------------+-------------+-------------+-----------------+
```

| field        | len | notes                                                   |
| ------------ | --- | ------------------------------------------------------- |
| `version`    | 1   | `= 0x01`. Unlock rejects any other value.               |
| `salt`       | 16  | random scrypt salt.                                     |
| `iv`         | 12  | random AES-GCM IV.                                      |
| `tag`        | 16  | AES-256-GCM auth tag, stored **before** the ciphertext. |
| `ciphertext` | N   | AES-256-GCM ciphertext of the private key (UTF-8).      |

Minimum payload length is `1+16+12+16 = 45` bytes.

### 2.3 Key schedule and AEAD

1. **KDF:** `key = scrypt(passphrase, salt, N = 2^14, r = 8, p = 1,
dklen = 32)`. `N = 2^14` matches Node's `scryptSync` interactive default.
2. **AEAD:** AES-256-GCM with the 12-byte IV and **empty AAD**, with the same
   `tag || ciphertext` wire order as §1.
3. **Unlock:** base64url-decode, require length ≥ 45, require version `0x01`,
   derive the key, GCM-decrypt, UTF-8-decode. **Any** failure yields `None`,
   which surfaces as the `INVALID_PASSPHRASE` error ("could not unlock <name>
   using passphrase").

Frozen: the version byte, field order, scrypt parameters, 12-byte IV, empty AAD,
and the collapse of every failure into `None` stay exactly as specified.
