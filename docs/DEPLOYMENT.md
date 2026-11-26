# Deployment

Resguardo is a boundary only if the application has no other way out. This guide covers where to put it so that holds, and what to run alongside it. The [threat model](THREAT_MODEL.md) assumes this deployment (assumption 1); the [lab](../lab/README.md) shows it with Docker.

## The rule

The application reaches the model through Resguardo and through nothing else. Resguardo reaches the providers in its `[[upstream]]` list and nothing else. Put both rules in the network, not only in configuration: a prompt injection that makes the application call an attacker's URL is stopped by the missing route, not by Resguardo.

## Docker

As in [`lab/docker-compose.yml`](../lab/docker-compose.yml):

- an `internal: true` network with the application and Resguardo: no route out;
- a second network for Resguardo only, with access to the providers.

The image (`Dockerfile`, target `runtime`) runs as a non-root user and keeps its data in `/data`. Mount the configuration read-only, and keep `/data` (log and keys) on a volume:

```console
$ docker run --rm -v resguardo-data:/data -v $PWD/resguardo.toml:/etc/resguardo/resguardo.toml:ro \
    resguardo init --config /etc/resguardo/resguardo.toml
$ docker run -d --restart unless-stopped --network internal -v resguardo-data:/data \
    -v $PWD/resguardo.toml:/etc/resguardo/resguardo.toml:ro resguardo
```

## Kubernetes

- Run Resguardo as its own Deployment behind a Service. A sidecar would share the application's network namespace and its routes out.
- A NetworkPolicy on the application's pods allows egress only to the Resguardo Service (and DNS).
- A NetworkPolicy on Resguardo's pods allows egress only to the providers' addresses.
- The signing key and provider credentials come from Secrets mounted as files with mode 0600, owned by the container's user. `resguardo init` can run once as a Job, writing to the persistent volume.

## Virtual machines

A firewall (nftables, a cloud security group) that drops the application host's outbound traffic except to Resguardo, and Resguardo's except to the providers. Resguardo listens on `127.0.0.1` by default; to serve other hosts, set `[server] listen` and see "Inbound traffic" below.

## A developer's laptop

Resguardo on a laptop, for example in front of Claude Code, is a guardrail, not a boundary: nothing stops other programs, or the agent itself, from reaching the internet directly. It helps catch mistakes, not a determined adversary.

## Inbound traffic

Resguardo speaks plain HTTP to applications in v0.1. On the same host or a private network that only the application and Resguardo share, that is enough. Across any other network, virtual keys and prompts would travel in clear: put a TLS terminator (a reverse proxy, a service mesh) in front, on the same host as Resguardo. Inbound TLS is planned (`LATER.md`).

## Operating it

- **One instance, one log, one key pair.** Several instances need their own audit log and key each. Their rate limits are per instance.
- **Back up the public key** away from the host: it is all an auditor needs, and it is how a log is trusted if the host is not.
- **Copy the audit log off the host** regularly. The chain proves that entries were not changed, but deleting the last entries leaves a valid, shorter log (threat model, section 7). A copy elsewhere closes that.
- **The log grows** without rotation in v0.1. Archive it while Resguardo is stopped, start a new file, and keep the old one with the public key that verifies it.
- **Restart policy:** Resguardo refuses to start if its configuration, key or log is not right. Restart on failure, and alert on repeated failures rather than looping silently.
- **Health:** `GET /healthz` answers 503 when the last audit write failed (a full disk, for example). While that lasts, every request is refused with `503 AUDIT_UNAVAILABLE` and nothing leaves.
- **Rotating the key:** `resguardo init --rotate-key` with Resguardo stopped, then start it again. The first public key still verifies the whole log.
