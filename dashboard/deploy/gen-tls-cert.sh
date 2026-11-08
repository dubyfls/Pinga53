#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Generate a self-signed TLS certificate for the dashboard. Called by
# install.sh on first start when PINGA53_TLS_CERT/KEY are not configured.
#
# Writes to /etc/pinga53/dashboard/tls/{cert.pem,key.pem}, mode 0600 for
# the key, 0644 for the cert, owned by the service user (pinga53).
#
# SAN list is derived from:
#   - the system hostname
#   - the box's non-loopback IPv4 addresses (so users can reach it by IP)
#
# Any existing files at the target paths are left alone; this script is a
# first-run bootstrap, not a rotation tool.
set -Eeuo pipefail
umask 077
export LC_ALL=C

TLS_DIR=${1:-/etc/pinga53/dashboard/tls}
SVC_USER=${2:-pinga53}
CERT="$TLS_DIR/cert.pem"
KEY="$TLS_DIR/key.pem"

mkdir -p -- "$TLS_DIR"
if [ -s "$CERT" ] && [ -s "$KEY" ]; then
  echo "tls: keeping existing $CERT + $KEY"
  exit 0
fi

HOST=$(hostname -s)
FQDN=$(hostname -f 2>/dev/null || echo "$HOST")

# non-loopback IPv4 addresses
IPS=$(ip -4 -o addr show scope global 2>/dev/null \
      | awk '{print $4}' | cut -d/ -f1 | sort -u | head -8 || true)

SAN="DNS:$HOST"
[ "$FQDN" != "$HOST" ] && SAN="$SAN,DNS:$FQDN"
for ip in $IPS; do
  SAN="$SAN,IP:$ip"
done

TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT

cat >"$TMP/openssl.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
x509_extensions = v3

[dn]
CN = $HOST

[v3]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = $SAN
EOF

openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) \
  -keyout "$KEY" -out "$CERT" -days 1825 -nodes \
  -config "$TMP/openssl.cnf" >/dev/null 2>&1

chmod 0644 "$CERT"
chmod 0600 "$KEY"
if id -u "$SVC_USER" >/dev/null 2>&1; then
  chown "$SVC_USER":"$SVC_USER" "$CERT" "$KEY" || true
fi

echo "tls: wrote $CERT (SAN: $SAN)"
