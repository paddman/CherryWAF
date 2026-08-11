# Ubuntu 26.04 LTS Appliance

CherryWAF v0.2 uses **Ubuntu Server 26.04 LTS amd64** as the primary virtual-appliance base.

## Image formats

```text
CherryWAF-VERSION-ubuntu-26.04-amd64.qcow2
CherryWAF-VERSION-ubuntu-26.04.ova
SHA256SUMS
```

The QCOW2 image targets Proxmox and KVM/QEMU. The OVA export targets VMware-compatible imports.

## Default sizing

| Resource | Default | Suggested production starting point |
|---|---:|---:|
| vCPU | 2 | 4 or more |
| RAM | 2 GiB | 4 to 8 GiB |
| Disk | 20 GiB | 40 GiB or more for local logs |
| NIC | VirtIO | Two NICs when separating management and data networks |

Sizing depends on request rate, body inspection limits, TLS workload, logging retention, and rule count.

## Build

```bash
make release-linux-amd64
packer init appliance/packer/ubuntu-26.04.pkr.hcl
packer build \
  -var-file=appliance/packer/variables.pkrvars.hcl \
  appliance/packer/ubuntu-26.04.pkr.hcl
```

The default ISO is the official Ubuntu 26.04 live-server amd64 image. Its SHA256 checksum is pinned in the Packer template.

## Clone safety

The Packer image is sealed before shutdown. The seal removes:

- `/etc/machine-id`;
- SSH host keys;
- the WAF local-admin token;
- the management TLS key pair;
- Control Center users/sessions/audit state;
- pending network rollback state.

Each cloned VM recreates unique values during `cherrywaf-firstboot.service`.
