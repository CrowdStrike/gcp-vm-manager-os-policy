terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  region = replace(var.zone, "/-[a-z]$/", "")
}

resource "google_compute_firewall" "deny_ssh_rdp" {
  name    = "${var.name_prefix}-deny-ssh-rdp"
  network = var.network

  deny {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = var.tags
  priority      = 1000
}

resource "google_compute_firewall" "allow_iap" {
  name    = "${var.name_prefix}-allow-iap"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }

  source_ranges = ["35.235.240.0/20"]
  target_tags   = var.tags
  priority      = 900
}

locals {
  os_configs = {
    ubuntu-2204 = {
      image     = "ubuntu-os-cloud/ubuntu-2204-lts"
      disk_size = null
    }
    ubuntu-2404 = {
      image     = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
      disk_size = null
    }
    debian-11 = {
      image     = "debian-cloud/debian-11"
      disk_size = null
    }
    debian-12 = {
      image     = "debian-cloud/debian-12"
      disk_size = null
    }
    debian-13 = {
      image     = "debian-cloud/debian-13"
      disk_size = null
    }
    rhel-8 = {
      image     = "rhel-cloud/rhel-8"
      disk_size = null
    }
    rhel-9 = {
      image     = "rhel-cloud/rhel-9"
      disk_size = null
    }
    rhel-10 = {
      image     = "rhel-cloud/rhel-10"
      disk_size = null
    }
    centos-stream-9 = {
      image     = "centos-cloud/centos-stream-9"
      disk_size = null
    }
    centos-stream-10 = {
      image     = "centos-cloud/centos-stream-10"
      disk_size = null
    }
    oracle-8 = {
      image     = "oracle-linux-cloud/oracle-linux-8"
      disk_size = null
    }
    oracle-9 = {
      image     = "oracle-linux-cloud/oracle-linux-9"
      disk_size = null
    }
    oracle-10 = {
      image     = "oracle-linux-cloud/oracle-linux-10"
      disk_size = null
    }
    sles-12-sp5 = {
      image     = "suse-cloud/sles-12-sp5-v20251022-x86-64"
      disk_size = null
    }
    sles-15 = {
      image     = "suse-cloud/sles-15"
      disk_size = null
    }
    windows-2022 = {
      image     = "windows-cloud/windows-2022"
      disk_size = 50
    }
  }

  enabled_os = { for k, v in local.os_configs : k => v if contains(var.enabled_os_list, k) }
}

resource "google_compute_instance" "os_instances" {
  for_each = local.enabled_os

  name                      = "${var.name_prefix}-${each.key}"
  machine_type              = var.machine_type
  zone                      = var.zone
  allow_stopping_for_update = true

  boot_disk {
    initialize_params {
      image = each.value.image
      size  = each.value.disk_size
    }
  }

  network_interface {
    network    = var.network
    subnetwork = var.subnetwork != "" ? var.subnetwork : null
  }

  tags   = var.tags
  labels = var.labels

  metadata = {
    enable-osconfig    = "TRUE"
    osconfig-log-level = "debug"
  }

  service_account {
    scopes = ["cloud-platform"]
  }
}
