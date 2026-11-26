#!/usr/bin/env bash
# The lab's attack without Docker: a real `resguardo run` in front of the mock provider, on
# this machine, then the same attack straight to the mock. It shows what Resguardo does to
# the traffic; the network isolation of the Docker lab cannot be shown here.
#   lab/local-demo.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

wait_for() { for _ in $(seq 1 50); do curl -s -o /dev/null "$1" && return 0; sleep 0.2; done; return 1; }

cargo build -q -p resguardo -p resguardo-mock-upstream --manifest-path "$ROOT/Cargo.toml"
BIN="$ROOT/target/debug"

KEY=$("$BIN/resguardo" key create --principal lab-app 2>"$WORK/key.err")
HASH=$(sed -n 's/.*key_sha256 = "\(.*\)".*/\1/p' "$WORK/key.err")
sed -e "s/@KEY_SHA256@/$HASH/" \
    -e 's|listen = "0.0.0.0:8787".*|listen = "127.0.0.1:18788"|' \
    -e 's|/data/|'"$WORK"'/|' \
    -e 's|base_url = "https://provider"|base_url = "http://127.0.0.1:19100"\nallow_insecure_upstream = true|' \
    "$ROOT/lab/resguardo.toml.in" > "$WORK/resguardo.toml"
"$BIN/resguardo" init --config "$WORK/resguardo.toml" >/dev/null 2>&1

"$BIN/mock-upstream" --listen 127.0.0.1:19100 >"$WORK/mock.log" 2>&1 & PIDS+=($!)
python3 -I -c '
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print("ATTACKER RECEIVED:", self.path, flush=True); self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 19101), H).serve_forever()' >"$WORK/attacker.log" 2>&1 & PIDS+=($!)
wait_for http://127.0.0.1:19100/__mock/requests
OPENAI_API_KEY=sk-lab-fake "$BIN/resguardo" run --config "$WORK/resguardo.toml" >"$WORK/resguardo.log" 2>&1 & PIDS+=($!)
wait_for http://127.0.0.1:18788/healthz

export KEY ATTACKER=http://127.0.0.1:19101 SKIP_NETWORK_CHECK=1
TARGET=http://127.0.0.1:18788 sh "$ROOT/lab/attack.sh" && protected=0 || protected=$?
echo
TARGET=http://127.0.0.1:19100 sh "$ROOT/lab/attack.sh" && unprotected=0 || unprotected=$?
echo
echo "== receipts"
(cd "$WORK" && "$BIN/resguardo" verify-log audit.jsonl --pubkey signing.pub)
echo "== exit codes: protected $protected, unprotected $unprotected"
