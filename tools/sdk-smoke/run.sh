#!/usr/bin/env bash
# Runs the official OpenAI and Anthropic Python SDKs against Resguardo in front of the mock
# upstream (milestone M1 done criterion).
#
# Never contacts a real provider: every upstream is 127.0.0.1, and `resguardo run` refuses
# non-local upstreams anyway. Needs cargo and uv (https://docs.astral.sh/uv/).
# SDK versions are pinned with hashes in requirements.txt; regenerate it with:
#   uv pip compile --universal --python-version 3.12 --generate-hashes --no-header \
#     tools/sdk-smoke/requirements.in -o tools/sdk-smoke/requirements.txt
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
UV=${UV:-uv}
MOCK_PORT=${MOCK_PORT:-19000}
PROXY_PORT=${PROXY_PORT:-18787}
WORK=$(mktemp -d)
MOCK_PID=""
RESGUARDO_PID=""

cleanup() {
  for pid in $RESGUARDO_PID $MOCK_PID; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

wait_for() {
  for _ in $(seq 1 50); do
    curl -s -o /dev/null "$1" && return 0
    sleep 0.2
  done
  echo "timed out waiting for $1" >&2
  return 1
}

cargo build -q -p resguardo -p resguardo-mock-upstream --manifest-path "$ROOT/Cargo.toml"
BIN="$ROOT/target/debug"

# Fake provider credentials, owner-only as Resguardo requires.
printf 'sk-fake-openai-key\n' > "$WORK/openai.key"
printf 'sk-ant-fake-key\n' > "$WORK/anthropic.key"
chmod 600 "$WORK/openai.key" "$WORK/anthropic.key"

# A fresh virtual key for this run; only its hash goes into the config.
KEY=$("$BIN/resguardo" key create --principal sdk-smoke 2>"$WORK/key.err")
HASH=$(sed -n 's/.*key_sha256 = "\(.*\)".*/\1/p' "$WORK/key.err")

cat > "$WORK/resguardo.toml" <<EOF
[server]
listen = "127.0.0.1:$PROXY_PORT"

[audit]
path = "$WORK/audit.jsonl"
signing_key = "$WORK/signing.key"
public_key = "$WORK/signing.pub"

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
base_url = "http://127.0.0.1:$MOCK_PORT"
credential_file = "$WORK/openai.key"
allow_insecure_upstream = true

[[upstream]]
provider = "anthropic"
base_url = "http://127.0.0.1:$MOCK_PORT"
credential_file = "$WORK/anthropic.key"
allow_insecure_upstream = true

[[principal]]
id = "sdk-smoke"
key_sha256 = "$HASH"
models.openai = ["gpt-4.1-mini"]
models.anthropic = ["claude-sonnet-5-5"]
EOF

# The signing key pair for the audit log (M5): nothing runs without it.
"$BIN/resguardo" init --config "$WORK/resguardo.toml" >/dev/null 2>&1

"$BIN/mock-upstream" --listen "127.0.0.1:$MOCK_PORT" >"$WORK/mock.log" 2>&1 &
MOCK_PID=$!
wait_for "http://127.0.0.1:$MOCK_PORT/__mock/requests"

"$BIN/resguardo" run --config "$WORK/resguardo.toml" >"$WORK/resguardo.log" 2>&1 &
RESGUARDO_PID=$!
wait_for "http://127.0.0.1:$PROXY_PORT/healthz"

"$UV" venv --quiet --python 3.12 "$WORK/venv"
"$UV" pip install --quiet --python "$WORK/venv/bin/python" --require-hashes \
  -r "$ROOT/tools/sdk-smoke/requirements.txt"

RESGUARDO_URL="http://127.0.0.1:$PROXY_PORT" RESGUARDO_KEY="$KEY" \
  "$WORK/venv/bin/python" -I "$ROOT/tools/sdk-smoke/smoke.py"

# What reached the "provider": only the configured fake credentials, never the virtual key.
REQUESTS=$(curl -s "http://127.0.0.1:$MOCK_PORT/__mock/requests")
if printf '%s' "$REQUESTS" | grep -q "rsg_"; then
  echo "FAIL a virtual key reached the upstream" >&2
  exit 1
fi
echo "ok   no virtual key reached the upstream"

# Every request left signed receipts that verify with the public key.
"$BIN/resguardo" verify-log "$WORK/audit.jsonl" --pubkey "$WORK/signing.pub" | sed 's/^.*: /ok   audit log verifies: /' 
