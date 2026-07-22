# Secret-manager resolvers

envrypt can replace a `<scheme>://…` env value with the secret read from an
external manager's CLI at load time. Every resolver is:

- **opt-in** — off by default; a stored reference loads verbatim unless the
  caller enables that scheme (least-privilege: enable only the managers you use).
- **fail-closed** — a reference you asked to resolve but couldn't (CLI absent,
  not authenticated, bad reference, timeout, empty output) is an ERROR, never a
  silent pass-through.
- **CLI-only** — envrypt shells the vendor CLI through the bounded subprocess
  `Exec` seam (no async, no cloud SDK — the crate's dep budget forbids
  `reqwest`/`hyper`/AWS-SDK), injection-safe (argv, never a shell string), and
  static-musl-friendly.
- **mocked in tests** — every resolver's tests inject a canned `Exec`, so the
  suite never spawns a real CLI or touches the network.

## Supported schemes

| Scheme         | Manager                      | Reference form                                                     | CLI invoked                                                                               | Opt-in flag                    | Docs                                                                                                           |
| -------------- | ---------------------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| `op://`        | 1Password                    | `op://<vault>/<item>/<field>`                                      | `op read <ref> --no-newline`                                                              | `resolve_op_references`        | [1Password CLI `op read`](https://developer.1password.com/docs/cli/reference/commands/read/)                   |
| `bw://`        | Bitwarden                    | `bw://<item-uuid>/<field>` (field ∈ `username`\|`password`\|`uri`) | `bw get <field> <item-uuid>`                                                              | `resolve_bw_references`        | [Bitwarden CLI `get`](https://bitwarden.com/help/cli/#get)                                                     |
| `vault://`     | HashiCorp Vault              | `vault://<path>#<field>`                                           | `vault kv get -field=<field> <path>`                                                      | `resolve_vault_references`     | [Vault `kv get`](https://developer.hashicorp.com/vault/docs/commands/kv)                                       |
| `aws://`       | AWS Secrets Manager          | `aws://<secret-id>`                                                | `aws secretsmanager get-secret-value --secret-id <id> --query SecretString --output text` | `resolve_aws_references`       | [`get-secret-value`](https://docs.aws.amazon.com/cli/latest/reference/secretsmanager/get-secret-value.html)    |
| `doppler://`   | Doppler                      | `doppler://<name>`                                                 | `doppler secrets get <name> --plain`                                                      | `resolve_doppler_references`   | [Doppler CLI secrets](https://docs.doppler.com/docs/accessing-secrets)                                         |
| `gcp://`       | GCP Secret Manager           | `gcp://<secret-name>`                                              | `gcloud secrets versions access latest --secret=<name>`                                   | `resolve_gcp_references`       | [`gcloud secrets versions access`](https://docs.cloud.google.com/sdk/gcloud/reference/secrets/versions/access) |
| `azure://`     | Azure Key Vault              | `azure://<vault>/<name>`                                           | `az keyvault secret show --vault-name <vault> --name <name> --query value -o tsv`         | `resolve_azure_references`     | [`az keyvault secret`](https://learn.microsoft.com/en-us/cli/azure/keyvault/secret)                            |
| `infisical://` | Infisical                    | `infisical://<name>`                                               | `infisical secrets get <name> --plain --silent`                                           | `resolve_infisical_references` | [Infisical CLI secrets](https://infisical.com/docs/cli/commands/secrets)                                       |
| `pass://`      | `pass` (Unix password store) | `pass://<path>`                                                    | `pass show <path>`                                                                        | `resolve_pass_references`      | [passwordstore.org](https://www.passwordstore.org/)                                                            |

Docs URLs verified against the vendors' current documentation (July 2026); they
are the canonical CLI command pages, not version-pinned — a CLI's flags can shift
across major versions.

## Authentication is the caller's responsibility

envrypt never authenticates a manager — it only invokes an already-authenticated
CLI and inherits its session from the process environment:

- **Vault** — `VAULT_ADDR` + `VAULT_TOKEN` (or a logged-in `~/.vault-token`).
- **AWS** — the standard credential chain (`AWS_PROFILE`, env keys, SSO).
- **Doppler** — `doppler login` / a `DOPPLER_TOKEN` service token.
- **GCP** — `gcloud auth` application-default credentials.
- **Azure** — `az login`.
- **Infisical** — `infisical login` / an `INFISICAL_TOKEN`.
- **Bitwarden** — an unlocked `BW_SESSION`.
- **1Password** — a signed-in `op` (optionally biometric).
- **`pass`** — a `gpg-agent` able to decrypt the store.

A locked/unauthenticated CLI exits non-zero, which envrypt surfaces as a
fail-closed resolution error (never a silent miss).

## Adding another resolver

Each scheme lives in `crates/envrypt/src/resolvers/<name>.rs` and follows one
shape (mirror `bitwarden.rs`): a `<SCHEME>_PREFIX` const, a `DEFAULT_*_TIMEOUT`,
an `is_*_reference`, a `parse_*_reference` (validate + extract the CLI args), a
`read_*_reference` (run the CLI via `Exec`, fail-closed, strip one trailing
newline), a `resolve_*_references` (in-place over the map), a `*Error` enum with
`reference()` + `message()`, and `#[cfg(test)]` tests driven by a canned `Exec`.
Wire it into `resolvers/mod.rs`, the `errors.rs` `*_resolution_failed`
constructor, the `ConfigOptions`/`LoadOptions` opt-in + timeout fields, and the
`config()` post-pass. Rank of remaining managers to add:
`.claude/reports/secret-resolver-ranking.md`.
