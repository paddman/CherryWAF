#!/usr/bin/env bash
set -euo pipefail
umask 0027

install -d -o root -g cherrywaf -m 0770 /etc/cherrywaf
install -d -o cherrywaf -g cherrywaf -m 0750 /var/lib/cherrywaf/control
install -d -o root -g cherrywaf -m 0750 /var/lib/cherrywaf/management
install -d -o root -g root -m 0700 /var/lib/cherrywaf/network
install -d -o root -g cherrywaf -m 0750 /run/cherrywaf

env_file=/etc/cherrywaf/cherrywaf.env
admin_token=""
setup_token=""
if [[ -r "$env_file" ]]; then
  admin_token="$(sed -n 's/^CHERRYWAF_ADMIN_TOKEN=//p' "$env_file" | tail -n1 | tr -d '\r\n')"
  setup_token="$(sed -n 's/^CHERRYWAF_SETUP_TOKEN=//p' "$env_file" | tail -n1 | tr -d '\r\n')"
fi
rewrite_env=false
if [[ ! "$admin_token" =~ ^[0-9a-f]{64}$ ]]; then
  admin_token="$(openssl rand -hex 32)"
  rewrite_env=true
fi
if [[ ! "$setup_token" =~ ^[0-9a-f]{16}$ ]]; then
  setup_token="$(openssl rand -hex 8)"
  rewrite_env=true
fi
if [[ "$rewrite_env" == true ]]; then
  tmp_env="$(mktemp /etc/cherrywaf/.env.XXXXXX)"
  printf 'CHERRYWAF_ADMIN_TOKEN=%s\nCHERRYWAF_SETUP_TOKEN=%s\n' "$admin_token" "$setup_token" >"$tmp_env"
  chown root:cherrywaf "$tmp_env"
  chmod 0640 "$tmp_env"
  mv -f "$tmp_env" "$env_file"
fi
chown root:cherrywaf "$env_file"
chmod 0640 "$env_file"

cert_dir=/var/lib/cherrywaf/management
cert_file="$cert_dir/fullchain.pem"
key_file="$cert_dir/privkey.pem"
regenerate=false
if [[ ! -s "$cert_file" || ! -s "$key_file" ]]; then
  regenerate=true
elif ! openssl x509 -in "$cert_file" -noout -checkend 86400 >/dev/null 2>&1; then
  regenerate=true
elif ! openssl pkey -in "$key_file" -noout -check >/dev/null 2>&1; then
  regenerate=true
elif ! cmp -s \
  <(openssl x509 -in "$cert_file" -pubkey -noout 2>/dev/null) \
  <(openssl pkey -in "$key_file" -pubout 2>/dev/null); then
  regenerate=true
fi

if [[ "$regenerate" == true ]]; then
  hostname_value="$(hostname -f 2>/dev/null || hostname)"
  hostname_value="${hostname_value:-cherrywaf}"
  openssl_config="$(mktemp)"
  trap 'rm -f "$openssl_config"' EXIT
  {
    cat <<CONFIG
[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no

[dn]
CN = ${hostname_value}
O = CherryWAF Appliance

[v3_req]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${hostname_value}
DNS.2 = cherrywaf
DNS.3 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
CONFIG
    index=3
    while IFS= read -r address; do
      [[ -n "$address" ]] || continue
      printf 'IP.%d = %s\n' "$index" "$address"
      index=$((index + 1))
    done < <(ip -o addr show scope global | awk '{split($4,a,"/"); print a[1]}' | sort -u)
  } >"$openssl_config"

  tmp_key="$(mktemp "$cert_dir/.privkey.XXXXXX")"
  tmp_cert="$(mktemp "$cert_dir/.fullchain.XXXXXX")"
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
    -config "$openssl_config" -extensions v3_req \
    -keyout "$tmp_key" -out "$tmp_cert"
  chown root:cherrywaf "$tmp_key" "$tmp_cert"
  chmod 0640 "$tmp_key" "$tmp_cert"
  mv -f "$tmp_key" "$key_file"
  mv -f "$tmp_cert" "$cert_file"
fi
chown root:cherrywaf "$key_file" "$cert_file"
chmod 0640 "$key_file" "$cert_file"

management_ip="$(ip -o -4 addr show scope global | awk 'NR==1 {split($4,a,"/"); print a[1]}')"
management_ip="${management_ip:-127.0.0.1}"
install -d -m 0755 /etc/issue.d
if [[ -r /var/lib/cherrywaf/control/state.json ]] && jq -e '.setup_completed == true' /var/lib/cherrywaf/control/state.json >/dev/null 2>&1; then
  setup_line="Control Center administrator is configured."
else
  setup_line="First-boot setup code: ${setup_token}"
fi
cat >/etc/issue.d/cherrywaf.issue <<ISSUE

CherryWAF Appliance
Management UI: https://${management_ip}:9443
${setup_line}

ISSUE
chmod 0644 /etc/issue.d/cherrywaf.issue
