#!/usr/bin/env bash
set -euo pipefail

host="${CHERRYWAF_TEST_HOST:-app.example.test}"
http_port="${CHERRYWAF_HTTP_PORT:-8080}"
https_port="${CHERRYWAF_HTTPS_PORT:-8443}"

printf 'Testing benign request...\n'
curl --noproxy '*' --fail --silent --show-error --resolve "${host}:${https_port}:127.0.0.1" \
  --insecure "https://${host}:${https_port}/" >/dev/null

printf 'Testing XSS block...\n'
status="$(curl --noproxy '*' --silent --output /dev/null --write-out '%{http_code}' \
  --resolve "${host}:${https_port}:127.0.0.1" --insecure \
  "https://${host}:${https_port}/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")"
if [[ "$status" != "403" ]]; then
  printf 'Expected 403, got %s\n' "$status" >&2
  exit 1
fi

printf 'Testing HTTP redirect...\n'
status="$(curl --noproxy '*' --silent --output /dev/null --write-out '%{http_code}' \
  --resolve "${host}:${http_port}:127.0.0.1" "http://${host}:${http_port}/")"
if [[ "$status" != "308" ]]; then
  printf 'Expected 308, got %s\n' "$status" >&2
  exit 1
fi

printf 'CherryWAF smoke tests passed.\n'
