# Getting started

Resguardo is pre-alpha. Everything below runs against the mock provider in `tools/mock-upstream`: no real API is called and no API key is needed. To use a real provider, point an `[[upstream]]` at it with `https://` and its credential.

## Requirements

- A stable Rust toolchain. `rust-toolchain.toml` pins it.
- A C compiler, used to build the TLS crypto library (`aws-lc-rs`).
- For the SDK demo only: [uv](https://docs.astral.sh/uv/).

## The one-command demo

```console
$ tools/sdk-smoke/run.sh
```

It builds Resguardo, starts the mock provider and Resguardo with a fresh virtual key and fake credentials, installs the official OpenAI and Anthropic Python SDKs (pinned by hash), and checks that:

- both SDKs get answers through Resguardo;
- unknown keys and models outside the list raise each SDK's usual exception;
- no virtual key ever reaches the provider.

## Step by step

Build the binaries and work in a scratch folder:

```console
$ cargo build -p resguardo -p resguardo-mock-upstream
$ export PATH="$PWD/target/debug:$PATH"
$ mkdir -p /tmp/resguardo-demo && cd /tmp/resguardo-demo
```

**1. Start the mock provider.** It speaks the OpenAI and Anthropic APIs and records every request it receives.

```console
$ mock-upstream --listen 127.0.0.1:9000 &
mock-upstream listening on http://127.0.0.1:9000
```

**2. Store a provider credential.** A fake one is fine for the mock. Resguardo refuses to start if the file is readable by anyone but its owner.

```console
$ printf 'sk-fake-openai\n' > openai.key && chmod 600 openai.key
```

**3. Create a virtual key for your application.** The key goes to stdout once; keep it. Only its hash goes into the configuration.

```console
$ resguardo key create --principal demo-app
rsg_<43 random Base62 characters>
Virtual key for principal 'demo-app' printed on stdout. It is shown only once: store it now.
Add this line to the [[principal]] entry with id = "demo-app":

    key_sha256 = "<64 hex characters>"
```

**4. Write the configuration.** Every field is validated; an unknown field or an unsafe value stops startup. The full reference with comments is [`config/resguardo.example.toml`](../config/resguardo.example.toml).

```toml
# resguardo.toml
[audit]
path = "audit.jsonl"
signing_key = "signing.key"
public_key = "signing.pub"

[policy.actions]
secret = "block"
secret_candidate = "flag"
es_id = "redact"
iban = "redact"
card = "block"
phone = "redact"
email = "redact"
invisible_text = "redact"

[[upstream]]
provider = "openai"
base_url = "http://127.0.0.1:9000"
credential_file = "openai.key"
allow_insecure_upstream = true      # plain HTTP, accepted only for local hosts

[[principal]]
id = "demo-app"
key_sha256 = "<the hash from step 3>"
models.openai = ["gpt-4.1-mini"]
```

```console
$ resguardo config check --config resguardo.toml
warning: [[upstream]] #1 (openai): plain HTTP to http://127.0.0.1:9000 (allow_insecure_upstream)
resguardo.toml: OK (1 upstream(s), 1 principal(s))
```

**5. Create the signing key pair.** Every authenticated request leaves two signed entries in the audit log, and Resguardo does not start without the key that signs them. `init` never replaces an existing key.

```console
$ resguardo init --config resguardo.toml
Signing key: signing.key (owner-only). Public key: signing.pub. Give the public key to auditors:
ed25519:<43 Base64url characters>
```

**6. Start Resguardo.**

```console
$ resguardo run --config resguardo.toml &
resguardo listening on http://127.0.0.1:8787
```

**7. Call it as if it were OpenAI.** Use the virtual key from step 3.

```console
$ curl -s http://127.0.0.1:8787/v1/chat/completions \
    -H "authorization: Bearer rsg_..." -H "content-type: application/json" \
    -d '{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"hola"}]}'
{"choices":[{"finish_reason":"stop","index":0,"message":{"content":"echo: hola","role":"assistant"}}],…}
```

A model outside the key's list is refused before anything leaves:

```console
$ curl -s http://127.0.0.1:8787/v1/chat/completions \
    -H "authorization: Bearer rsg_..." -H "content-type: application/json" \
    -d '{"model":"gpt-5","messages":[{"role":"user","content":"hola"}]}'
{"error":{"code":"MODEL_NOT_ALLOWED","message":"this model is not allowed for this key","request_id":"01a213b0-…","type":"resguardo_policy_violation"}}
```

**8. See what reached the "provider".** Only the configured credential, never the virtual key:

```console
$ curl -s http://127.0.0.1:9000/__mock/requests
```

**9. Verify the receipts.** Anyone with the public key can check that no entry was changed, removed or reordered. The log holds metadata only: principal, model, sizes, hashes, finding classes and counts, decision, status and latencies, never prompt content.

```console
$ resguardo verify-log audit.jsonl --pubkey signing.pub
audit.jsonl: OK (4 entries)
$ head -1 audit.jsonl
{"body_bytes":75,"body_sha256":"…","decision":"allow","findings":{},"flags":{},"hash":"…","kind":"decision","model":"gpt-4.1-mini","prev":"000…","principal":"demo-app","provider":"openai","request_id":"…","seq":1,"sig":"…","stream":false,"ts":"…"}
```

`verify-log` exits with 1 and names the first line that fails and why (`hash`, `sig`, `prev`, `seq` or `format`). To replace the key pair, `resguardo init --rotate-key` records the rotation in the log, signed with the old key; the first public key still verifies the whole log. If the receipt for a request cannot be written (a full disk, say), the request is refused with `503 AUDIT_UNAVAILABLE` and nothing leaves.

Stop both with `kill %1 %2`. Resguardo finishes the requests in flight on Ctrl-C or `SIGTERM`.

## Using the official SDKs

Change the base URL and the key; nothing else.

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8787/v1", api_key="rsg_...")
client.chat.completions.create(model="gpt-4.1-mini", messages=[{"role": "user", "content": "hola"}])
```

```python
from anthropic import Anthropic

client = Anthropic(base_url="http://127.0.0.1:8787", api_key="rsg_...")  # or auth_token="rsg_..."
client.messages.create(model="claude-sonnet-5-5", max_tokens=256, messages=[{"role": "user", "content": "hola"}])
```

Streaming works with both SDKs (`stream=True`, `messages.stream(...)`). Claude Code works the same way through `ANTHROPIC_BASE_URL`; see [running Claude Code through Resguardo](research/claude-code-gateway.md).

## Responses and streaming

Responses are scanned too ([ADR 0014](adr/0014-streaming-and-response-controls.md)):

- A secret or another class whose action is `block` stops the response. A whole response becomes a `403 SENSITIVE_DATA`; a stream gets an `event: error` with the same JSON and is closed. The SDKs raise their usual exception (`APIError`, `APIStatusError`).
- Remote Markdown images (`![x](https://...)`) become `[image removed]`, and links to hosts outside `[response] allowed_link_hosts` keep only their text. After a prompt injection, an image is the usual way to send data out: the client loads its URL, with the data in it, without a click.
- With `stream_mode = "passthrough_abort"` (the default), events are sent as soon as they are scanned, so the first part of a secret split across events reaches the application before the stream is cut. With `stream_mode = "buffer"`, events wait for the end of a sentence (or `buffer_flush_bytes`), and nothing of it is released.

## Scanning a text

`resguardo scan` runs the detectors on a file or on standard input, without a configuration or a running proxy. It prints the data class, the rule, the byte range and the decoding layers of each finding, never the value, so the output is safe to paste into a ticket.

```console
$ echo "deploy token: QUtJQUlPU0ZPRE5ON0VYQU1QTEU=" | resguardo scan
finding  secret  secret.aws_access_key  bytes 14..42  confidence 90  via base64
1 finding, 0 flags
```

A `flag` line means a limit was reached (for example, more encoding layers than `max_decode_depth`), so part of the text was not fully checked. The command exits with 1 when there is any finding or flag, so it can stop a git hook or a CI job: `resguardo scan --file .env || exit 1`. Input over 1 MiB or not valid UTF-8 is refused with exit code 2, never scanned in part.

## Errors

Resguardo answers in the error shape of the API that was called, so each SDK raises its usual exception. The body carries Resguardo's code and the request id, and never any request content.

```jsonc
// /v1/messages: Anthropic's shape
{"type":"error","error":{"type":"permission_error","code":"MODEL_NOT_ALLOWED","message":"this model is not allowed for this key"},"request_id":"01a213a9-…"}

// /v1/chat/completions: OpenAI's shape
{"error":{"type":"resguardo_error","code":"UNKNOWN_KEY","message":"unknown or missing virtual key","request_id":"01a213a9-…"}}
```

| Code | HTTP | When |
| --- | --- | --- |
| `INVALID_REQUEST` | 400 | Malformed JSON, duplicate keys, unknown query parameters, compressed body |
| `UNKNOWN_KEY` / `KEY_EXPIRED` | 401 | Missing, unknown, ambiguous or expired virtual key |
| `MODEL_NOT_ALLOWED` | 403 | Provider or model outside the key's list |
| `SENSITIVE_DATA` | 403 | A finding whose action is `block`, in the request or the response (the message names its class, never the value), or encoded content too deep to inspect |
| `NOT_FOUND` | 404 | Any route other than `POST /v1/chat/completions` and `POST /v1/messages` |
| `BODY_TOO_LARGE` | 413 | Body or message count over the key's limit |
| `RATE_LIMITED` | 429 | Over the key's requests per minute; `retry-after` says when to retry |
| `SCAN_ERROR` | 500 | Scanning or redaction failed; nothing was sent |
| `AUDIT_UNAVAILABLE` | 503 | The signed receipt could not be written; nothing was sent |
| `UPSTREAM_REDIRECT` / `UPSTREAM_ERROR` | 502 | The provider redirected, failed or could not be reached |

Errors from the provider itself are passed through unchanged. Every response carries `x-resguardo-request-id` and `x-resguardo-decision` (`allow`, `redact` or `block`).

### Exit codes of the command line

Every command exits with 0 when it did its job and the answer is yes, 1 when it did its job and the answer is no (for example, `config check` found an invalid configuration), and 2 when it could not do its job (an unreadable file, invalid arguments). See [ADR 0009](adr/0009-cli-exit-codes.md).
