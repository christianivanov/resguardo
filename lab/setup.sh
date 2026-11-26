#!/bin/sh
# First start of the lab: a virtual key for the application, the configuration with its
# hash, and the audit signing key pair. Nothing secret is stored in the repository.
set -eu
if [ ! -f /data/resguardo.toml ]; then
  resguardo key create --principal lab-app >/labkey/app.key 2>/tmp/key.err
  hash=$(sed -n 's/.*key_sha256 = "\(.*\)".*/\1/p' /tmp/key.err)
  sed "s/@KEY_SHA256@/$hash/" /lab/resguardo.toml.in >/data/resguardo.toml
  chmod 644 /labkey/app.key
fi
resguardo init --config /data/resguardo.toml >/dev/null 2>&1 || true
