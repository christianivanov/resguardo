# Changelog

## v0.1.0 (unreleased)

The first release: an egress boundary for LLM traffic between applications and the OpenAI and Anthropic APIs, or any OpenAI-compatible server.

### Proxy

- OpenAI Chat Completions and Anthropic Messages, with and without streaming. The official SDKs work unchanged: only the base URL and the key change.
- Virtual keys: 256 random bits, only their SHA-256 stored; the application never sees a provider key.
- Closed by default: only listed providers and models; HTTPS with the operating system's verifier and post-quantum key exchange; no redirects or retries; any internal error blocks the request.
- Strict parsing: what the scanner reads is what the provider reads; requests without findings are forwarded byte for byte.

### Detection and policy

- Secrets with known formats and by entropy; Spanish DNI, NIE and CIF, IBAN for every country in the SWIFT registry, cards with Luhn, Spanish phones and email addresses.
- De-obfuscation: NFKC, invisible characters, Base64, hexadecimal and URL-encoding up to two layers.
- Actions per data class and per principal: `allow`, `flag`, `redact` or `block`. Redaction rewrites only the affected strings, with stable numbering (`[REDACTED:es_id:1]`).
- Responses are scanned too. Streams use a 256-byte overlap window and are cut with an error event; remote Markdown images and links outside an allowlist are removed.

### Receipts

- A hash-chained, Ed25519-signed audit log with RFC 8785 canonicalization. The decision is on disk before anything leaves, or the request is refused. `resguardo verify-log` checks it with the public key, and `resguardo init --rotate-key` rotates the key.

### Tooling

- `resguardo scan`, `accuracy`, `config check`, `key create`, `init` and `verify-log`.
- An accuracy corpus with published false-positive rates, a benchmark, fuzz targets for the SSE parser and the response controls, an exfiltration lab with Docker, and a deployment guide.

### Known limits

See the [threat model](docs/THREAT_MODEL.md#7-explicitly-not-protected-in-v01).
