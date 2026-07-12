#!/usr/bin/env bash
# Generate a CA and one node certificate for the gossip mutual-TLS link.
# Point every node's [gossip.tls] at ca.crt, and give each its own node cert/key.
# Usage: scripts/gen-certs.sh [out-dir] [node-name]
set -euo pipefail
DIR="${1:-certs}"
NAME="${2:-fedserv}"
mkdir -p "$DIR"
cd "$DIR"

if [ ! -f ca.crt ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout ca.key -out ca.crt -days 3650 -subj "/CN=fedserv-ca"
fi

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$NAME.key" -out "$NAME.csr" -subj "/CN=$NAME"
openssl x509 -req -in "$NAME.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$NAME.crt" -days 3650 \
    -extfile <(printf "subjectAltName=DNS:%s" "$NAME")
rm -f "$NAME.csr" ca.srl

echo "wrote $DIR/{ca.crt, $NAME.crt, $NAME.key}"
