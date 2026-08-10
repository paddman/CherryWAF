#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
install -d -m 0755 /usr/local/bin
install -m 0755 /tmp/cherrywaf-build/cherrywaf /usr/local/bin/cherrywaf
install -m 0755 /tmp/cherrywaf-build/cherrywafctl /usr/local/bin/cherrywafctl

install -m 0644 /tmp/cherrywaf-build/cherrywaf.sysusers /usr/lib/sysusers.d/cherrywaf.conf
systemd-sysusers /usr/lib/sysusers.d/cherrywaf.conf
install -m 0644 /tmp/cherrywaf-build/cherrywaf.tmpfiles /usr/lib/tmpfiles.d/cherrywaf.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/cherrywaf.conf

install -o root -g cherrywaf -m 0640 /tmp/cherrywaf-build/cherrywaf.json /etc/cherrywaf/cherrywaf.json
install -o root -g root -m 0644 /tmp/cherrywaf-build/cherrywaf.service /etc/systemd/system/cherrywaf.service
install -o root -g root -m 0644 /tmp/cherrywaf-build/cherrywaf.logrotate /etc/logrotate.d/cherrywaf

admin_token="$(openssl rand -hex 32)"
printf 'CHERRYWAF_ADMIN_TOKEN=%s\n' "$admin_token" > /etc/cherrywaf/cherrywaf.env
chown root:root /etc/cherrywaf/cherrywaf.env
chmod 0600 /etc/cherrywaf/cherrywaf.env

printf '%s\n' "${CHERRYWAF_APPLIANCE_VERSION:-dev}" > /etc/cherrywaf/appliance-version
chmod 0644 /etc/cherrywaf/appliance-version

/usr/local/bin/cherrywaf validate-config --config /etc/cherrywaf/cherrywaf.json
systemctl daemon-reload
systemctl enable cherrywaf.service
systemctl restart cherrywaf.service

# Keep the token out of the console. A local administrator can retrieve it with:
# sudo cat /etc/cherrywaf/cherrywaf.env
rm -rf /tmp/cherrywaf-build
