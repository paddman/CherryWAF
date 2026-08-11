packer {
  required_version = ">= 1.14.0"
  required_plugins {
    qemu = {
      version = "~> 1.1"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

variable "appliance_version" {
  type    = string
  default = "0.2.0-dev"
}

variable "iso_url" {
  type    = string
  default = "https://releases.ubuntu.com/26.04/ubuntu-26.04-live-server-amd64.iso"
}

variable "iso_checksum" {
  type    = string
  default = "sha256:dec49008a71f6098d0bcfc822021f4d042d5f2db279e4d75bdd981304f1ca5d9"
}

variable "admin_username" {
  type    = string
  default = "cherryadmin"
}

variable "admin_password_hash" {
  type      = string
  sensitive = true
}

variable "ssh_private_key_file" {
  type      = string
  sensitive = true
}

variable "ssh_public_key_file" {
  type = string
}

variable "timezone" {
  type    = string
  default = "Asia/Bangkok"
}

variable "cpus" {
  type    = number
  default = 2
}

variable "memory_mb" {
  type    = number
  default = 2048
}

variable "disk_size" {
  type    = string
  default = "20G"
}

variable "accelerator" {
  type    = string
  default = "kvm"
}

variable "headless" {
  type    = bool
  default = true
}

variable "output_directory" {
  type    = string
  default = "appliance/output-cherrywaf"
}

variable "cherrywaf_binary" {
  type    = string
  default = "dist/linux-amd64/cherrywaf"
}

variable "cherrywafctl_binary" {
  type    = string
  default = "dist/linux-amd64/cherrywafctl"
}

variable "control_binary" {
  type    = string
  default = "dist/linux-amd64/cherrywaf-control"
}

variable "netd_binary" {
  type    = string
  default = "dist/linux-amd64/cherrywaf-netd"
}

source "qemu" "cherrywaf" {
  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  output_directory = var.output_directory
  vm_name          = "CherryWAF-${var.appliance_version}-ubuntu-26.04-amd64.qcow2"

  format           = "qcow2"
  disk_size        = var.disk_size
  disk_interface   = "virtio"
  disk_compression = true
  net_device       = "virtio-net"
  accelerator      = var.accelerator
  cpus             = var.cpus
  memory           = var.memory_mb
  headless         = var.headless

  boot_wait = "8s"
  boot_command = [
    "<esc><wait>",
    "e<wait>",
    "<down><down><down><end>",
    " autoinstall ds=nocloud-net\\;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/",
    "<f10>"
  ]

  http_content = {
    "/meta-data" = file(abspath("${path.root}/../http/meta-data"))
    "/user-data" = templatefile(abspath("${path.root}/../http/user-data.pkrtpl.hcl"), {
      admin_username      = var.admin_username
      admin_password_hash = var.admin_password_hash
      ssh_public_key      = trimspace(file(var.ssh_public_key_file))
      timezone            = var.timezone
    })
  }

  communicator           = "ssh"
  ssh_username           = var.admin_username
  ssh_private_key_file   = var.ssh_private_key_file
  ssh_timeout            = "45m"
  pause_before_connecting = "10s"
  shutdown_command       = "sudo /usr/local/sbin/cherrywaf-image-seal"
}

build {
  name    = "cherrywaf-appliance"
  sources = ["source.qemu.cherrywaf"]

  provisioner "shell" {
    inline = ["mkdir -p /tmp/cherrywaf-build"]
  }

  provisioner "file" {
    source      = var.cherrywaf_binary
    destination = "/tmp/cherrywaf-build/cherrywaf"
  }

  provisioner "file" {
    source      = var.cherrywafctl_binary
    destination = "/tmp/cherrywaf-build/cherrywafctl"
  }

  provisioner "file" {
    source      = var.control_binary
    destination = "/tmp/cherrywaf-build/cherrywaf-control"
  }

  provisioner "file" {
    source      = var.netd_binary
    destination = "/tmp/cherrywaf-build/cherrywaf-netd"
  }

  provisioner "file" {
    source      = "appliance/scripts/firstboot.sh"
    destination = "/tmp/cherrywaf-build/cherrywaf-firstboot"
  }

  provisioner "file" {
    source      = "configs/cherrywaf.appliance.json"
    destination = "/tmp/cherrywaf-build/cherrywaf.json"
  }

  provisioner "file" {
    source      = "deployments/systemd/cherrywaf.service"
    destination = "/tmp/cherrywaf-build/cherrywaf.service"
  }

  provisioner "file" {
    source      = "deployments/systemd/cherrywaf-control.service"
    destination = "/tmp/cherrywaf-build/cherrywaf-control.service"
  }

  provisioner "file" {
    source      = "deployments/systemd/cherrywaf-firstboot.service"
    destination = "/tmp/cherrywaf-build/cherrywaf-firstboot.service"
  }

  provisioner "file" {
    source      = "deployments/systemd/cherrywaf-netd.service"
    destination = "/tmp/cherrywaf-build/cherrywaf-netd.service"
  }

  provisioner "file" {
    source      = "deployments/systemd/cherrywaf-netd.socket"
    destination = "/tmp/cherrywaf-build/cherrywaf-netd.socket"
  }

  provisioner "file" {
    source      = "deployments/systemd/cherrywaf.sysusers"
    destination = "/tmp/cherrywaf-build/cherrywaf.sysusers"
  }

  provisioner "file" {
    source      = "deployments/systemd/cherrywaf.tmpfiles"
    destination = "/tmp/cherrywaf-build/cherrywaf.tmpfiles"
  }

  provisioner "file" {
    source      = "deployments/systemd/cherrywaf.logrotate"
    destination = "/tmp/cherrywaf-build/cherrywaf.logrotate"
  }

  provisioner "shell" {
    environment_vars = ["CHERRYWAF_APPLIANCE_VERSION=${var.appliance_version}"]
    execute_command  = "chmod +x {{ .Path }}; sudo -E {{ .Vars }} {{ .Path }}"
    scripts = [
      "appliance/scripts/provision.sh",
      "appliance/scripts/hardening.sh"
    ]
  }

  post-processor "checksum" {
    checksum_types      = ["sha256"]
    keep_input_artifact = true
    output              = "${var.output_directory}/SHA256SUMS"
  }
}
