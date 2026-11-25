# Resguardo

> An egress boundary for LLM traffic: nothing leaves without policy, and every decision leaves a signed receipt.

*resguardo* (Spanish): both a safeguard and a receipt.

Resguardo is a single Rust binary that sits between your application and the OpenAI and Anthropic APIs. Only allowed destinations and models get through, secrets and personal data are redacted or blocked, and every decision is recorded in a hash-chained, Ed25519-signed log that anyone can verify with the public key.

## Status

Pre-alpha. Nothing works yet; the repository currently contains only the workspace skeleton. Do not use it to protect anything.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
