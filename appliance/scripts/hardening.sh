#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y upgrade
apt-get install -y --no-install-recommends \
  auditd ca-certificates curl iproute2 jq netplan.io nftables openssl qemu-guest-agent unattended-upgrades
apt-get autoremove -y
apt-get clean
rm -rf /var/lib/apt/lists/*

cat >/etc/sysctl.d/60-cherrywaf-hardening.conf <<'SYSCTL'
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
SYSCTL
sysctl --system >/dev/null

install -d -m 0755 /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/60-cherrywaf-hardening.conf <<'SSHD'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding local
PermitOpen 127.0.0.1:9090 127.0.0.1:9443
GatewayPorts no
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
SSHD
sshd -t
systemctl restart ssh.service

cat >/etc/nftables.conf <<'NFT'
#!/usr/sbin/nft -f
flush ruleset

table inet cherrywaf_filter {
  chain input {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept
    udp sport 67 udp dport 68 accept
    udp sport 547 udp dport 546 accept
    tcp dport { 22, 80, 443, 9443 } ct state new accept
  }

  chain forward {
    type filter hook forward priority filter; policy drop;
  }

  chain output {
    type filter hook output priority filter; policy accept;
  }
}
NFT
nft -c -f /etc/nftables.conf
systemctl enable --now nftables.service auditd.service qemu-guest-agent.service unattended-upgrades.service

cat >/etc/apt/apt.conf.d/52cherrywaf-unattended-upgrades <<'APT'
Unattended-Upgrade::Allowed-Origins {
  "${distro_id}:${distro_codename}-security";
  "${distro_id}ESMApps:${distro_codename}-apps-security";
  "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
APT

# Packer invokes this as its shutdown command. Remove all clone-specific state
# so each VM creates unique host keys, WAF credentials, and management TLS.
cat >/usr/local/sbin/cherrywaf-image-seal <<'SEAL'
#!/usr/bin/env bash
set -euo pipefail
systemctl stop cherrywaf-control.service cherrywaf.service cherrywaf-netd.socket 2>/dev/null || true
rm -f /etc/cherrywaf/cherrywaf.env
rm -rf /var/lib/cherrywaf/management /var/lib/cherrywaf/control /var/lib/cherrywaf/network
cloud-init clean --logs --seed || true
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -sf /etc/machine-id /var/lib/dbus/machine-id
rm -f /etc/ssh/ssh_host_*
sync
/sbin/poweroff
SEAL
chmod 0750 /usr/local/sbin/cherrywaf-image-seal

sync
