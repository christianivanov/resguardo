# 0005. Generic OpenAI-compatible upstream in v0.1

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

Most teams that call LLMs already have something in the path: a gateway (LiteLLM, Bifrost, Portkey) or a self-hosted server (vLLM, Ollama). Almost all of them expose the OpenAI Chat Completions format at their own URL.

With only OpenAI and Anthropic as upstreams, adopting Resguardo means replacing that component. With a generic upstream, Resguardo can sit **in front of** what a team already runs, so it complements their gateway instead of competing with it. The design document listed this as the first item to add "if ahead of schedule"; it is moved into v0.1 because it is cheap and changes who can adopt Resguardo.

## Decision

- A third provider, `openai_compatible`, speaks the OpenAI Chat Completions format (same normalization, same SSE parser) at a configured `base_url`.
- v0.1 allows **at most one upstream per provider**.
- Routing: `POST /v1/chat/completions` goes to `openai` or `openai_compatible` depending on **which of the principal's lists contains the requested model**. A principal listing the same model under both providers is a configuration error, so routing is never ambiguous.
- The credential is optional for `openai_compatible`, because local servers often have none. When neither `credential_env` nor `credential_file` is set, Resguardo still strips the application's own key and sends no `Authorization` header.
- Every other rule stays: HTTPS only unless `allow_insecure_upstream` with a local host, no redirects, the same scanning, policy and audit log.

## Consequences

- Resguardo can be deployed in front of an existing gateway or a self-hosted model with a config change.
- One more value for `Provider` in the code, config and audit log, and tests against the mock upstream for it.
- It adds no new API format: only the OpenAI format at a different URL. Formats that differ subtly from OpenAI's will still be forwarded unchanged when fields are unknown.
- Several upstreams of the same provider (for example two vLLM servers) stay out of scope → `LATER.md`.
