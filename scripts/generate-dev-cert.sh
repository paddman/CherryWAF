#!/usr/bin/env bash
set -euo pipefail

domain="${1:-app.example.test}"
out="${2:-var/certs/${domain}}"
mkdir -p "$out"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -subj "/CN=${domain}" \
  -addext "subjectAltName=DNS:${domain}" \
  -keyout "$out/privkey.pem" \
  -out "$out/fullchain.pem"
chmod 0600 "$out/privkey.pem"
chmod 0644 "$out/fullchain.pem"
printf 'Certificate: %s\nPrivate key: %s\n' "$out/fullchain.pem" "$out/privkey.pem"
