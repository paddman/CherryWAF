# CherryWAF Virtual Appliance

CherryWAF v0.2 builds a hardened virtual appliance from **Ubuntu Server 26.04 LTS amd64**. The primary artifact is QCOW2 for KVM/Proxmox, with an OVA conversion path for VMware-compatible imports.

## Default virtual hardware

| Resource | Default | Suggested pilot starting point |
|---|---:|---:|
| vCPU | 2 | 4 or more |
| Memory | 2 GiB | 4 to 8 GiB |
| Disk | 20 GiB thin-provisioned | 40 GiB or more for local logs |
| NIC | VirtIO | Two NICs when separating management and data |
| Firmware | BIOS | Match the target virtualization platform |
| Disk format | QCOW2 | QCOW2 or converted OVA |

Requirements depend on request rate, TLS handshakes, request-body limits, rule count, and log retention.

## Installed services

| Service | Purpose |
|---|---|
| `cherrywaf-firstboot.service` | Generate unique clone-specific secrets and management TLS |
| `cherrywaf.service` | WAF data plane and loopback admin API |
| `cherrywaf-control.service` | Browser GUI on HTTPS port 9443 |
| `cherrywaf-netd.socket` | Group-restricted privileged network helper socket |
| `cherrywaf-netd.service` | Netplan apply/confirm/rollback and fixed WAF restart action |

The appliance also installs nftables, auditd, qemu-guest-agent, OpenSSL, Netplan, and unattended security updates.

## Network exposure

```text
22/tcp     SSH maintenance
80/tcp     WAF HTTP
443/tcp    WAF HTTPS
9443/tcp   CherryWAF Control Center
```

The WAF admin API remains bound to `127.0.0.1:9090` and is not opened by nftables.

## Build requirements

Build on Linux with:

- Packer 1.14 or newer
- QEMU/KVM and `qemu-img`
- Go 1.26.5 or compatible pinned toolchain support
- OpenSSL
- an SSH key pair dedicated to image construction

```bash
sudo apt-get install -y qemu-kvm qemu-utils openssl
ssh-keygen -t ed25519 -f ~/.ssh/cherrywaf_packer -N ''
cp appliance/packer/variables.pkrvars.hcl.example \
   appliance/packer/variables.pkrvars.hcl
openssl passwd -6
```

Set the resulting password hash and SSH key paths in `variables.pkrvars.hcl`, then run:

```bash
make appliance
```

The template pins the official Ubuntu 26.04 live-server amd64 ISO and its SHA-256 checksum.

For validation without KVM acceleration:

```hcl
accelerator = "tcg"
```

TCG is substantially slower and is not recommended for routine builds.

## First boot

The sealed golden image contains no shared WAF token, setup code, Control Center user, management TLS private key, machine ID, or SSH host key.

At first boot:

1. `cherrywaf-firstboot.service` generates unique local credentials and a self-signed management certificate.
2. The console shows the management URL and one-time Control Center setup code.
3. Open `https://APPLIANCE-IP:9443` and claim the first administrator.
4. Configure network settings, install frontend certificates, and add protected applications.
5. Begin new applications in detect mode before enabling blocking.

The SSH maintenance account is defined by the Packer variables. SSH password authentication is disabled; use the matching private key.

## Proxmox import

```bash
qm create 9000 --name CherryWAF --memory 4096 --cores 4 \
  --net0 virtio,bridge=vmbr0
qm importdisk 9000 \
  appliance/output-cherrywaf/CherryWAF-*.qcow2 local-lvm
qm set 9000 --scsihw virtio-scsi-pci \
  --scsi0 local-lvm:vm-9000-disk-0
qm set 9000 --boot order=scsi0 --agent enabled=1
```

Adapt VM ID, datastore, bridge, CPU, and memory values to the target cluster.

## VMware OVA export

```bash
./appliance/scripts/export-ova.sh \
  appliance/output-cherrywaf/CherryWAF-0.2.0-ubuntu-26.04-amd64.qcow2 \
  appliance/output-cherrywaf/CherryWAF-0.2.0-ubuntu-26.04.ova
```

Validate the generated OVA with the target VMware tooling before publishing it.

## First-site CLI fallback

The GUI is the normal appliance management path, but the local CLI remains available:

```bash
sudo cherrywafctl cert install \
  --domain app.example.com \
  --cert ./fullchain.pem \
  --key ./privkey.pem \
  --owner root \
  --group cherrywaf

sudo cherrywafctl vhost upsert \
  --name app \
  --domain app.example.com \
  --upstream https://10.10.10.20:443 \
  --origin-server-name origin.internal.example.com \
  --cert /etc/cherrywaf/certs/app.example.com/fullchain.pem \
  --key /etc/cherrywaf/certs/app.example.com/privkey.pem
```

## Image security notes

- Clone only from the sealed artifact, not from a running configured appliance.
- Replace the image-construction SSH key during deployment or inject operational keys through automation.
- Keep origin certificate verification enabled. `insecure_skip_verify` is for controlled diagnostics only.
- Trust or replace the initial self-signed management certificate according to the management-PKI policy.
- Backups intentionally exclude private keys and are not complete disaster-recovery exports.
- The GitHub workflow validates the Packer template on a hosted runner, but producing QCOW2/OVA requires a self-hosted KVM runner.
