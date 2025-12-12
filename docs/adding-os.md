# Adding Operating System Support

This guide explains how to add support for a new operating system or OS version to the GCP VM Manager OS Policy tool.

## Architecture Overview

Add a new OS involves modifying the following files.

1. **Policy Struct** - Defines OS-specific resource fields
2. **OS Mapping** - Maps sensor identifiers to policy fields
3. **Sensor Configuration** - Defines how to discover and fetch sensor binaries

## OS Short Name Reference

When adding support for a new OS, use the correct short name identifier. The following table was pulled from the [Os Policy Assignment](https://docs.cloud.google.com/compute/vm-manager/docs/os-policies/working-with-os-policies#os-policy-assignment) documentation. 

| Full Name                           | Short Name      |
| ----------------------------------- | --------------- |
| CentOS                              | `centos`        |
| Container-Optimized OS (COS)        | `cos`           |
| Debian                              | `debian`        |
| openSUSE Leap                       | `opensuse-leap` |
| Oracle Linux                        | `ol`            |
| Red Hat Enterprise Linux (RHEL)     | `rhel`          |
| Rocky Linux                         | `rocky`         |
| SUSE Linux Enterprise Server (SLES) | `sles`          |
| Ubuntu                              | `ubuntu`        |
| Windows Server                      | `windows`       |

## Step-by-Step Guide

### 1. Update Policy Struct

**File:** `internal/policy/policy.go`

Add a new field to the `Policy` struct:

```go
type Policy struct {
    // ... existing fields ...
    NewOs9 osResource  // Description of the new OS
}
```

**Naming Convention:**
- Use the OS short name + version number (e.g., `Centos9`, `Rhel9`, `Sles15`)
- For OS without version-specific handling, use just the name (e.g., `Debian`, `Ubuntu`)

### 2. Add OS Version Mapping

**File:** `internal/policy/policy.go`

In the `NewPolicy()` function, add an entry to the `osVersionToField` map:

```go
osVersionToField := map[string]*osResource{
    // ... existing mappings ...
    "newos9*": &policy.NewOs9,
}
```

**Mapping Key Format:**
- Combine `osShortName` + `osVersion` from sensor definition
- Use wildcard `*` to match all point releases (e.g., `"centos7*"` matches 7.0, 7.1, 7.9)
- For version-agnostic OS, omit the wildcard (e.g., `"debian"`)

### 3. Add Sensor Definition

**File:** `pkg/cmd/create/create.go`

Add a new entry to the `targetSensors` array:

```go
targetSensors := []sensor.Sensor{
    // ... existing sensors ...
    {
        Filter:       "os:'*NewOS*'+os_version:'9'+platform:'linux'",
        OsShortName:  "newos",
        OsVersion:    "9*",
        BucketPrefix: "crowdstrike/falcon/{cloud}/linux/newos/9",
    },
}
```

**Field Descriptions:**
- `Filter` - CrowdStrike API query filter to discover sensors
- `OsShortName` - Short OS identifier (lowercase, used in mapping)
- `OsVersion` - Version pattern with wildcard (must match mapping key)
- `BucketPrefix` - GCS bucket path where sensor binaries are stored

**Platform Values:**
- `linux` - Linux-based systems
- `windows` - Windows systems

### 4. Update OS Policy Template

**File:** `internal/policy/template.json`

Add a new resource group for the OS:

```json
{
  "inventoryFilters": [
    {
      "osShortName": "newos",
      "osVersion": "9*"
    }
  ],
  "resources": [
    {
      "id": "newos9-install",
      "pkg": {
        "desiredState": "INSTALLED",
        "rpm": {
          "source": {
            "gcs": {
              "bucket": "{{ .NewOs9.Bucket }}",
              "object": "{{ .NewOs9.Object }}",
              "generation": {{ .NewOs9.Generation }}
            }
          }
        }
      }
    },
    {
      "id": "newos9-configure",
      "exec": {
        "validate": {
          "interpreter": "SHELL",
          "script": "systemctl is-active falcon-sensor"
        },
        "enforce": {
          "interpreter": "SHELL",
          "script": "systemctl start falcon-sensor && /opt/CrowdStrike/falconctl -s -f --cid={{ .Cid }} --tags={{ .SensorGroupingTags }} --apd=false --aph={{ .Aph }} --app={{ .App }}"
        }
      }
    }
  ]
}
```

**Template Variables:**
- `.NewOs9.Bucket` - GCS bucket name (populated from sensor data)
- `.NewOs9.Object` - GCS object path (populated from sensor data)
- `.NewOs9.Generation` - GCS object generation ID
- `.Cid` - CrowdStrike Customer ID
- `.SensorGroupingTags` - Sensor grouping tags
- `.Aph`, `.App` - Proxy configuration

## Package Type Differences

### RPM-Based Systems (CentOS, RHEL)

```json
"pkg": {
  "desiredState": "INSTALLED",
  "rpm": {
    "source": {
      "gcs": { /* bucket info */ }
    }
  }
}
```

### DEB-Based Systems (Debian, Ubuntu)

```json
"pkg": {
  "desiredState": "INSTALLED",
  "deb": {
    "source": {
      "gcs": { /* bucket info */ }
    }
  }
}
```

### SUSE Systems (SLES)

Uses custom `exec` resource with zypper commands instead of `pkg` resource.

### Windows Systems

Uses `exec` resource with PowerShell script for MSI installation.

## Example: Adding CentOS 9

### 1. Policy Struct
```go
Centos9 osResource  // CentOS 9
```

### 2. OS Mapping
```go
"centos9*": &policy.Centos9,
```

### 3. Sensor Definition
```go
{
    Filter:       "os:'*CentOS*'+os_version:'9'+platform:'linux'",
    OsShortName:  "centos",
    OsVersion:    "9*",
    BucketPrefix: "crowdstrike/falcon/{cloud}/linux/centos/9",
},
```

### 4. Template Resource Group
```json
{
  "inventoryFilters": [
    {
      "osShortName": "centos",
      "osVersion": "9*"
    }
  ],
  "resources": [
    {
      "id": "centos9-install",
      "pkg": {
        "desiredState": "INSTALLED",
        "rpm": {
          "source": {
            "gcs": {
              "bucket": "{{ .Centos9.Bucket }}",
              "object": "{{ .Centos9.Object }}",
              "generation": {{ .Centos9.Generation }}
            }
          }
        }
      }
    },
    {
      "id": "centos9-configure",
      "exec": {
        "validate": {
          "interpreter": "SHELL",
          "script": "systemctl is-active falcon-sensor"
        },
        "enforce": {
          "interpreter": "SHELL",
          "script": "systemctl start falcon-sensor && /opt/CrowdStrike/falconctl -s -f --cid={{ .Cid }} --tags={{ .SensorGroupingTags }} --apd=false --aph={{ .Aph }} --app={{ .App }}"
        }
      }
    }
  ]
}
```

## Verification Checklist

Before implementing support for a new OS:

- [ ] Verify CrowdStrike provides sensors for this OS
- [ ] Confirm the correct bucket path in GCS
- [ ] Validate the API filter matches the OS correctly
- [ ] Determine the correct package type (RPM, DEB, MSI, or custom)
- [ ] Check if standard installation commands work for this OS
- [ ] Verify service management commands (`systemctl`, `service`, etc.)

## Data Flow

```
Sensor Discovery (CrowdStrike API)
    ↓
Sensor Download (GCS bucket)
    ↓
OS Mapping (osShortName + osVersion → Policy field)
    ↓
Template Rendering (Go templates with sensor metadata)
    ↓
OS Policy JSON Generation
    ↓
GCP VM Manager Deployment
```
