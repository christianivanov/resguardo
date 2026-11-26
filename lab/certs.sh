#!/bin/sh
# A CA and a certificate for "provider", once. Lab only: these keys are thrown away.
set -eu
cd /certs
[ -f provider.pem ] && exit 0
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=Resguardo lab CA" \
  -keyout ca-key.pem -out ca.pem
openssl req -newkey rsa:2048 -nodes -subj "/CN=provider" \
  -keyout provider-key.pem -out provider.csr
printf 'subjectAltName=DNS:provider\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > ext.cnf
openssl x509 -req -in provider.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -days 30 -extfile ext.cnf -out provider.pem
chmod 644 ca.pem provider.pem provider-key.pem
