# Security policy

Resguardo is a security boundary, so a flaw in it matters more than in most software. Thank you for reporting one privately.

## Reporting a vulnerability

Use GitHub's private reporting: **Security → Report a vulnerability** on this repository. Please do not open a public issue, pull request or discussion about it.

A useful report says:
- what an attacker can do, and from where (the application, the model's answer, the network, the host);
- the smallest request, stream or configuration that shows it;
- the commit you tested.

Use invented secrets and personal data only, and a local mock provider ([`tools/mock-upstream`](tools/mock-upstream)) instead of a real one.

## What counts

Anything that breaks a promise in the [threat model](docs/THREAT_MODEL.md), for example:
- sensitive data that a detector should find reaches the provider, or a destination or model that is not allowed gets a request;
- an error in scanning, policy, audit, signing or configuration lets a request through (Resguardo must fail closed);
- the scanner and the provider read different values from the same request;
- an audit log that was changed, reordered or truncated in the middle still verifies;
- a virtual key, provider credential, signing key or request content is written to a log;
- a crash, hang or unbounded memory use caused by a request or a stream.

The limits listed in the [threat model](docs/THREAT_MODEL.md#7-explicitly-not-protected-in-v01) and in the [README](README.md#limits) are known and not vulnerabilities, but a cheaper way to exploit one is still worth reporting.

## Supported versions

There is no release yet. Fixes go to `main`; once v0.1.0 is tagged, the latest release is supported.

## What to expect

This is a project maintained by one person, on a best-effort basis. The aim is to acknowledge a report within a week, agree on a fix and a disclosure date with you, and credit you in the advisory unless you prefer otherwise.
