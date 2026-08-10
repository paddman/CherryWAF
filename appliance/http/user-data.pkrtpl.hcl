#cloud-config
autoinstall:
  version: 1
  locale: en_US.UTF-8
  keyboard:
    layout: us
  timezone: ${timezone}
  identity:
    hostname: cherrywaf
    username: ${admin_username}
    password: '${admin_password_hash}'
  ssh:
    install-server: true
    allow-pw: false
    authorized-keys:
      - '${ssh_public_key}'
  packages:
    - auditd
    - ca-certificates
    - curl
    - jq
    - nftables
    - openssl
    - qemu-guest-agent
    - unattended-upgrades
  storage:
    layout:
      name: direct
  kernel:
    package: linux-generic
  updates: security
  late-commands:
    - curtin in-target --target=/target -- systemctl enable qemu-guest-agent.service
    - curtin in-target --target=/target -- systemctl enable unattended-upgrades.service
    - curtin in-target --target=/target -- sh -c 'printf "%s ALL=(ALL) NOPASSWD:ALL\\n" "${admin_username}" > /etc/sudoers.d/90-${admin_username}'
    - curtin in-target --target=/target -- chmod 0440 /etc/sudoers.d/90-${admin_username}
