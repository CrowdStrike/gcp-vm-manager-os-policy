package versionutil

import (
	"github.com/blang/semver/v4"
	"github.com/crowdstrike/gofalcon/falcon"
)

// ShouldUseCloudAgnosticPath determines whether a sensor version supports cloud-agnostic installation paths.
//
// Version-based cloud compatibility rules:
//
// Linux sensors:
//   - Version >= 7.28.0: Cloud-agnostic (no cloud in path needed)
//   - Version < 7.28.0: Cloud-specific path required
//
// Windows sensors:
//   - Version >= 7.26.0: Cloud-agnostic for all clouds including gov
//   - Version >= 7.19.0 and < 7.26.0:
//     * Commercial clouds (us-1, us-2, eu-1): Cloud-agnostic (share same installer)
//     * Gov clouds (us-gov-1): Cloud-specific path required
//   - Version < 7.19.0: Cloud-specific path required for all clouds
func ShouldUseCloudAgnosticPath(version string, platform string, cloud falcon.CloudType) bool {
	v, err := semver.ParseTolerant(version)
	if err != nil {
		return false
	}

	if platform == "linux" {
		minVersion := semver.MustParse("7.28.0")
		return v.GTE(minVersion)
	}

	if platform == "windows" {
		v726 := semver.MustParse("7.26.0")
		if v.GTE(v726) {
			return true
		}

		v719 := semver.MustParse("7.19.0")
		if v.GTE(v719) {
			switch cloud {
			case falcon.CloudUsGov1:
				return false
			default:
				return true
			}
		}
	}

	return false
}
