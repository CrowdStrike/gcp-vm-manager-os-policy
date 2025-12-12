variable "zone" {
  description = "GCP zone where instances will be created"
  type        = string
  default     = "us-central1-a"
}

variable "network" {
  description = "VPC network name"
  type        = string
  default     = "default"
}

variable "subnetwork" {
  description = "VPC subnetwork name (optional)"
  type        = string
  default     = ""
}

variable "name_prefix" {
  description = "Prefix for instance names"
  type        = string
  default     = "cs-policy-test"
}

variable "machine_type" {
  description = "Machine type for all instances"
  type        = string
  default     = "e2-medium"
}

variable "tags" {
  description = "Network tags to apply to all instances"
  type        = list(string)
  default     = ["cs-policy-test"]
}

variable "enabled_os_list" {
  description = "List of operating systems to enable"
  type        = list(string)
  default = [
    "ubuntu-2204",
    "ubuntu-2404",
    "debian-11",
    "debian-12",
    "debian-13",
    "rhel-8",
    "rhel-9",
    "rhel-10",
    "centos-stream-9",
    "centos-stream-10",
    "oracle-8",
    "oracle-9",
    "oracle-10",
    "sles-12-sp5",
    "sles-15",
    "windows-2022",
  ]
}

variable "labels" {
  description = "Labels to apply to all instances"
  type        = map(string)
  default = {
    purpose = "cs-policy-testing"
  }
}
