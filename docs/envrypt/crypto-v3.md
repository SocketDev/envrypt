# envrypt v3 - native encrypted-value format

This is the format envrypt **writes** when it encrypts a value. Older values
(the v1 layouts) stay **readable** so existing files keep working, but every new
value envrypt produces uses v3.

v3 exists to fix four concrete weaknesses in the older design. Read the "Why"
notes - each one maps to a real attack the format now blocks.

## The building blocks (and why each was chosen)

| Job                  | Algorithm                     | Why                                                                                                                  |
| -------------------- | ----------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Recipient encryption | **X25519** ECDH + HKDF-SHA256 | No point-validation footguns (unlike a signing curve used for encryption), 32-byte keys, fast.                       |
| Symmetric cipher     | **XChaCha20-Poly1305**        | 24-byte random nonce, so a fresh random nonce per value has no realistic reuse risk. Constant-time in pure software. |
| Passphrase → key     | **Argon2id**                  | Memory-hard; the current top recommendation for password-based keys. Far harder to crack on GPUs/ASICs than scrypt.  |
| Key check            | **Key commitment tag**        | Makes the cipher _committing_ - a blob can only ever open under one key.                                             |

All four are pure-Rust crates (`x25519-dalek`, `chacha20poly1305`,
`argon2`) - no OpenSSL, no C.

## Two modes

A v3 value is either **recipient** mode (encrypted to a public key; the private
key decrypts it) or **passphrase** mode (encrypted under a passphrase). Both
share the same header, AAD, and commitment rules; they differ only in how the
32-byte symmetric key is produced.

## The header (also the AAD)

Every v3 payload starts with a small header. Those exact header bytes are **also
passed to the cipher as AAD** (Additional Authenticated Data - data that is
authenticated but not encrypted), together with the **variable name**. If anyone
changes a header byte _or moves the value to a different variable_, decryption
fails.

```
offset  field          type      notes
------  -------------  --------  ------------------------------------------
  0     version        u8        0x03
  1     mode           u8        0x01 recipient | 0x02 passphrase
  2     aead_id        u8        0x01 XChaCha20-Poly1305
  3     kdf_id         u8        0x00 none (recipient) | 0x02 argon2id
------  passphrase-only KDF params (omitted when kdf_id = 0x00) -----------
  4     argon_t_cost   u32 BE    Argon2id time cost (default 3)
  8     argon_m_cost   u32 BE    Argon2id memory KiB (default 65536 = 64 MiB)
 12     argon_p        u8        Argon2id lanes (default 1)
```

**AAD fed to the cipher =** `header_bytes || 0x00 || variable_name_utf8`.
The `0x00` separator keeps a name like `AB` + header from colliding with `A` +
different bytes. The variable name is authenticated but never stored in the
payload - the caller already knows it (it's the `.env` key).

> **Why (relocation attack).** In the old format the private key decrypts _any_
> ciphertext no matter which variable it sits under, so an attacker with write
> access could move `encrypted:(DEBUG=false)` onto `ADMIN_ENABLED` and it would
> decrypt clean. Binding the variable name into the AAD means a value only opens
> under the name it was sealed for.

## Recipient mode (mode = 0x01) - the `encrypted:` value

```
encrypted:<base64url(payload)>

payload:
+---------+----------------+-------------+------------------+-----------+---------------+
| header  | eph_pub X25519 | nonce (24)  | commitment (32)  | tag (16)  | ciphertext(N) |
| 4 bytes | 32 bytes       |             |                  |           |               |
+---------+----------------+-------------+------------------+-----------+---------------+
```

Key schedule:

1. Generate a fresh ephemeral X25519 keypair for this value.
2. `shared = X25519(eph_priv, recipient_pub)`.
3. `key = HKDF-SHA256(ikm = shared, salt = ∅, info = "envrypt:v3:recip" || eph_pub, len = 32)`.
   Putting the ephemeral public key in `info` binds the key to this exact handshake.
4. Encrypt with XChaCha20-Poly1305 (fresh 24-byte random nonce, AAD as above).
5. Compute the commitment (below).

Detection: a v3 payload's first byte is `0x03`; a legacy v1 `encrypted:` payload
starts with `0x04`, a SEC1 point prefix, so the two never collide.

## Passphrase mode (mode = 0x02) - the `locked:` value

```
locked:<public_key_hex>:<base64url(payload)>

payload:
+---------+-----------+-------------+------------------+-----------+---------------+
| header  | salt (16) | nonce (24)  | commitment (32)  | tag (16)  | ciphertext(N) |
| 13 bytes|           |             |                  |           |               |
+---------+-----------+-------------+------------------+-----------+---------------+
```

Key schedule:

1. `key = Argon2id(passphrase, salt, t_cost, m_cost, p, len = 32)` with the
   params from the header.
2. Encrypt with XChaCha20-Poly1305 (fresh 24-byte random nonce, AAD as above).

Because the Argon2 params live in the header **and** the header is the AAD, an
attacker cannot silently downgrade the work factor: changing `m_cost` to a cheap
value breaks the tag. The decryptor also rejects params above sane ceilings
(`t_cost > 2^12`, `m_cost > 2^20 KiB`) **before** allocating, so a tampered
header cannot force a resource-exhaustion (memory-blowup) denial of service.

## Key commitment (both modes)

XChaCha20-Poly1305, like AES-GCM, is **not committing**: without extra work a
single blob can be crafted to open validly under more than one key. For a
passphrase format that enables a _partitioning oracle_ - each decrypt attempt
tests many candidate passphrases at once, speeding up cracking.

Fix: derive a 32-byte commitment from the key and store it in the payload:

```
commitment = HKDF-SHA256(ikm = key, salt = ∅, info = "envrypt:v3:commit", len = 32)
```

The decryptor recomputes `commitment` from its derived key and compares in
constant time **before** running the cipher. A wrong key (or wrong passphrase)
fails here, and a blob can only ever commit to one key.

> **Why (partitioning oracle).** Commitment turns "this ciphertext might open
> under many keys" into "this ciphertext opens under exactly one key," removing
> the multi-guess speedup against passphrases.

## Decrypt order (both modes)

1. base64url-decode; read the header; reject unknown `version`/`mode`/`aead_id`/`kdf_id`.
2. Derive the key (ECDH+HKDF, or Argon2id).
3. Recompute the commitment; constant-time compare. Mismatch → fail.
4. Rebuild the AAD (`header || 0x00 || var_name`); XChaCha20-Poly1305 decrypt.
5. UTF-8 the plaintext.

Any failure returns the same opaque error - never a distinct "wrong passphrase"
vs "wrong name" signal - so the format is not itself an oracle.

## Compatibility

- envrypt still **reads** the v1 `encrypted:` and `locked:` layouts (the
  interop tests prove it), so existing files keep decrypting.
- The **curated public API and default encrypt path write only v3.** A v1
  writer stays as a low-level primitive (`envrypt::crypto::encrypt_with_key`)
  that only the in-repo vector generator and benchmarks call - never the app
  path.
- Recipient v3 uses X25519 keys - a new keypair, generated by envrypt.

## Test obligations

- Round-trip every mode; wrong key / wrong passphrase / wrong variable name each fail.
- Tamper each header byte (version, mode, aead_id, every KDF param) → decrypt fails.
- Relocation: a value sealed for `A` fails to decrypt under name `B`.
- Commitment: a crafted multi-key blob fails the commitment check.
- Nonce uniqueness across a batch is asserted.
- Vectors are envrypt-generated (fresh keys + values), checked in for reproducibility.
