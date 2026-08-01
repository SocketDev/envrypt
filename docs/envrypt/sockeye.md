# Use Envrypt with Sockeye

Envrypt decrypts values only after its host process has a private key. For
local agent work, let Sockeye deliver that key to one exact approved program.
Do not give an agent a general command that reads Envrypt's private key.

## Setup

Store the Envrypt private key under its usual environment variable name:

```sh
pnpm run setup:credential -- ENVRYPT_PRIVATE_KEY
```

Run that command from a Sockeye checkout. Choose the recommended 1Password
import when it is offered. Sockeye stores the value in its Touch-ID-protected
Keychain entry. The value is not written to an Envrypt `.env.keys` file.

## Run a trusted host

Use an absolute executable and working directory in the approved command. For
example, a Node program that embeds Envrypt can be started this way:

```sh
sockeye run \
  --credential ENVRYPT_PRIVATE_KEY \
  --cwd /absolute/path/to/project \
  -- /absolute/path/to/node /absolute/path/to/project/app.mjs
```

Sockeye shows the executable, arguments, working directory, and credential name
before Touch ID. It passes the private key through a one-use inherited pipe.
The child receives only non-secret metadata naming the `envrypt-v1` protocol
and file descriptor. Its parent agent does not receive the key.

Envrypt's default `KeyPolicy::EnvOnly` reads the pipe before resolving files or
ambient environment variables. It checks the fixed protocol header, credential
name, length, and key shape; malformed data fails closed. After one read it
closes the descriptor. The received buffer is explicitly overwritten before its
allocation is released. Envrypt also overwrites its short-lived resolver copies
before releasing their allocations.

## Channel boundary

`envrypt-v1` is a per-process capability, not a daemon or secret lookup API.
Sockeye creates the pipe for one approved child, writes one bounded record, and
closes its end. Envrypt accepts exactly one record and does not expose a way to
retrieve it. This gives a subagent the key only when its exact program is the
Touch-ID-approved child.
