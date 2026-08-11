#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
install -d -m 0755 /usr/local/bin /usr/local/sbin
install -m 0755 /tmp/cherrywaf-build/cherrywaf /usr/local/bin/cherrywaf
install -m 0755 /tmp/cherrywaf-build/cherrywafctl /usr/local/bin/cherrywafctl
install -m 0755 /tmp/cherrywaf-build/cherrywaf-control /usr/local/bin/cherrywaf-control
install -m 0755 /tmp/cherrywaf-build/cherrywaf-netd /usr/local/sbin/cherrywaf-netd
install -m 0750 /tmp/cherrywaf-build/cherrywaf-firstboot /usr/local/sbin/cherrywaf-firstboot

install -m 0644 /tmp/cherrywaf-build/cherrywaf.sysusers /usr/lib/sysusers.d/cherrywaf.conf
systemd-sysusers /usr/lib/sysusers.d/cherrywaf.conf
install -m 0644 /tmp/cherrywaf-build/cherrywaf.tmpfiles /usr/lib/tmpfiles.d/cherrywaf.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/cherrywaf.conf

install -o root -g cherrywaf -m 0660 /tmp/cherrywaf-build/cherrywaf.json /etc/cherrywaf/cherrywaf.json
install -o root -g root -m 0644 /tmp/cherrywaf-build/cherrywaf.service /etc/systemd/system/cherrywaf.service
install -o root -g root -m 0644 /tmp/cherrywaf-build/cherrywaf-control.service /etc/systemd/system/cherrywaf-control.service
install -o root -g root -m 0644 /tmp/cherrywaf-build/cherrywaf-firstboot.service /etc/systemd/system/cherrywaf-firstboot.service
install -o root -g root -m 0644 /tmp/cherrywaf-build/cherrywaf-netd.service /etc/systemd/system/cherrywaf-netd.service
install -o root -g root -m 0644 /tmp/cherrywaf-build/cherrywaf-netd.socket /etc/systemd/system/cherrywaf-netd.socket
install -o root -g root -m 0644 /tmp/cherrywaf-build/cherrywaf.logrotate /etc/logrotate.d/cherrywaf

# The golden image must not contain clone-shared secrets. First boot generates
# a unique WAF admin token and management TLS certificate for every appliance.
: >/etc/cherrywaf/cherrywaf.env
chown root:cherrywaf /etc/cherrywaf/cherrywaf.env
chmod 0640 /etc/cherrywaf/cherrywaf.env

printf '%s\n' "${CHERRYWAF_APPLIANCE_VERSION:-dev}" > /etc/cherrywaf/appliance-version
chmod 0644 /etc/cherrywaf/appliance-version

/usr/local/bin/cherrywaf validate-config --config /etc/cherrywaf/cherrywaf.json
systemctl daemon-reload
systemctl enable cherrywaf-firstboot.service cherrywaf.service cherrywaf-control.service cherrywaf-netd.socket

# Services intentionally remain stopped during image construction so unique
# credentials are generated only after a cloned VM boots.
rm -rf /tmp/cherrywaf-build
