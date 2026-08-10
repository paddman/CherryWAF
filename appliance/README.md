# CherryWAF Virtual Appliance

CherryWAF Appliance is a hardened virtual machine image built from **Ubuntu Server 24.04.4 LTS Minimal** with the GA `linux-generic` kernel. The build produces a QCOW2 image for KVM/Proxmox and includes an OVA conversion script for VMware-compatible imports.

## Why Ubuntu Server 24.04.4 LTS

The appliance prioritizes a mature package base, predictable security maintenance, broad KVM/VMware guest support, and straightforward operations. Ubuntu 26.04 LTS is deliberately not the default for the first production appliance release. It can be evaluated after its first point release and a compatibility soak period.

## Default virtual hardware

| Resource | Default |
|---|---:|
| vCPU | 2 |
| Memory | 2 GB |
| Disk | 20 GB thin-provisioned |
| NIC | VirtIO |
| Firmware | BIOS |
| Disk format | QCOW2 |

Recommended production sizing starts at 4 vCPU and 8 GB RAM. Actual requirements depend on request rate, TLS handshakes, body inspection limits, and log retention.

## Installed components

- CherryWAF and `cherrywafctl`
- systemd service with capability and filesystem hardening
- nftables firewall allowing inbound TCP 22, 80, and 443
- unattended security updates
- auditd
- qemu-guest-agent
- structured JSON access and security logs

The admin API remains bound to `127.0.0.1:9090`. It is not exposed by the appliance firewall.

## Build requirements

Build on Linux with:

- Packer 1.14 or newer
- QEMU/KVM and `qemu-img`
- Go 1.26.5 or compatible toolchain support
- `openssl`
- an SSH key pair dedicated to image construction

```bash
sudo apt-get install -y qemu-kvm qemu-utils openssl
ssh-keygen -t ed25519 -f ~/.ssh/cherrywaf_packer -N ''
cp appliance/packer/variables.pkrvars.hcl.example \
   appliance/packer/variables.pkrvars.hcl
openssl passwd -6
```

Put the resulting SHA-512 password hash and SSH key paths into `variables.pkrvars.hcl`, then build:

```bash
make appliance
```

The template pins the official Ubuntu 24.04.4 live-server ISO SHA-256 checksum. Packer initializes the official HashiCorp QEMU plugin automatically through `make appliance-init`.

For environments without KVM acceleration, change this variable only for testing:

```hcl
accelerator = "tcg"
```

TCG image construction is substantially slower and is not recommended for routine builds.

## First boot

The default administrator account is configured in `variables.pkrvars.hcl`. Password login over SSH is disabled; use the corresponding SSH private key.

CherryWAF starts on port 80 with no virtual hosts. HTTPS remains disabled until a valid certificate is installed. This prevents an appliance-generated self-signed certificate from being mistaken for a production trust configuration.

Check service state:

```bash
sudo systemctl status cherrywaf
curl http://127.0.0.1:9090/healthz
sudo cat /etc/cherrywaf/cherrywaf.env
```

## Add the first HTTPS site

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

sudo cherrywaf validate-config --config /etc/cherrywaf/cherrywaf.json
sudo systemctl restart cherrywaf
```

A restart is required when HTTPS is enabled for the first time because the listener set changes. Later certificate and rule changes can use a hot reload:

```bash
sudo systemctl reload cherrywaf
```

## Proxmox import

```bash
qm create 9000 --name CherryWAF --memory 2048 --cores 2 --net0 virtio,bridge=vmbr0
qm importdisk 9000 appliance/output-cherrywaf/CherryWAF-*.qcow2 local-lvm
qm set 9000 --scsihw virtio-scsi-pci --scsi0 local-lvm:vm-9000-disk-0
qm set 9000 --boot order=scsi0 --agent enabled=1
```

Adapt VM ID, datastore, and bridge names to the target cluster.

## VMware OVA export

```bash
./appliance/scripts/export-ova.sh \
  appliance/output-cherrywaf/CherryWAF-0.1.0-ubuntu-24.04-amd64.qcow2 \
  CherryWAF-0.1.0.ova
```

Validate the generated OVA with the target VMware tooling before publishing it as a release artifact.

## Image security notes

- The build-specific machine ID and SSH host keys are removed during image sealing and regenerated on first boot.
- The CherryWAF admin token is generated inside each image build and stored in `/etc/cherrywaf/cherrywaf.env` with mode `0600`. Rotate it after cloning a golden image if clones are created from a running VM rather than the sealed artifact.
- The appliance administrator SSH key remains authorized. Replace it during deployment or use cloud-init/automation to inject an operational key.
- Keep origin certificate verification enabled. `insecure_skip_verify` exists only for controlled migration scenarios and defaults to `false`.
