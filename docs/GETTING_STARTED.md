# Getting started

Resguardo is pre-alpha. Until scanning (M2) and the signed audit log (M5) exist, `resguardo run` only accepts **local** upstreams, so everything below runs against the mock provider in `tools/mock-upstream`. No real API is ever called and no API key is needed.

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

**5. Start Resguardo.**

```console
$ resguardo run --config resguardo.toml &
resguardo listening on http://127.0.0.1:8787
```

**6. Call it as if it were OpenAI.** Use the virtual key from step 3.

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

**7. See what reached the "provider".** Only the configured credential, never the virtual key:

```console
$ curl -s http://127.0.0.1:9000/__mock/requests
```

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

Claude Code works the same way through `ANTHROPIC_BASE_URL`; it needs streaming, which arrives in M4. See [running Claude Code through Resguardo](research/claude-code-gateway.md).

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
| `INVALID_REQUEST` | 400 | Malformed JSON, duplicate keys, unknown query parameters, compressed body, streaming (until M4) |
| `UNKNOWN_KEY` / `KEY_EXPIRED` | 401 | Missing, unknown, ambiguous or expired virtual key |
| `MODEL_NOT_ALLOWED` | 403 | Provider or model outside the key's list |
| `NOT_FOUND` | 404 | Any route other than `POST /v1/chat/completions` and `POST /v1/messages` |
| `BODY_TOO_LARGE` | 413 | Body or message count over the key's limit |
| `RATE_LIMITED` | 429 | Over the key's requests per minute; `retry-after` says when to retry |
| `UPSTREAM_REDIRECT` / `UPSTREAM_ERROR` | 502 | The provider redirected, failed or could not be reached |

Errors from the provider itself are passed through unchanged. Every response carries `x-resguardo-request-id` and `x-resguardo-decision`.
