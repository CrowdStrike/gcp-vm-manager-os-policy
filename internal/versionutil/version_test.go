package versionutil

import (
	"testing"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/stretchr/testify/assert"
)

func TestShouldUseCloudAgnosticPath(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		platform string
		cloud    falcon.CloudType
		want     bool
	}{
		// Linux sensors: >= 7.28.0 cloud-agnostic, < 7.28.0 cloud-specific
		{
			name:     "Linux 7.28.0 commercial cloud should use cloud-agnostic path",
			version:  "7.28.0",
			platform: "linux",
			cloud:    falcon.CloudUs2,
			want:     true,
		},
		{
			name:     "Linux 7.29.15 commercial cloud should use cloud-agnostic path",
			version:  "7.29.15",
			platform: "linux",
			cloud:    falcon.CloudUs2,
			want:     true,
		},
		{
			name:     "Linux 7.30 commercial cloud should use cloud-agnostic path",
			version:  "7.30",
			platform: "linux",
			cloud:    falcon.CloudUs2,
			want:     true,
		},
		{
			name:     "Linux 8.0.12 gov cloud should use cloud-agnostic path",
			version:  "8.0.12",
			platform: "linux",
			cloud:    falcon.CloudUsGov1,
			want:     true,
		},
		{
			name:     "Linux 7.27.0 commercial cloud should use cloud-specific path",
			version:  "7.27.0",
			platform: "linux",
			cloud:    falcon.CloudUs2,
			want:     false,
		},
		{
			name:     "Linux 7.20.5 commercial cloud should use cloud-specific path",
			version:  "7.20.5",
			platform: "linux",
			cloud:    falcon.CloudUs2,
			want:     false,
		},
		{
			name:     "Linux 7.25.0 gov cloud should use cloud-specific path",
			version:  "7.25.0",
			platform: "linux",
			cloud:    falcon.CloudUsGov1,
			want:     false,
		},
		// Windows sensors: >= 7.26.0 all clouds cloud-agnostic
		{
			name:     "Windows 7.26.0 commercial cloud should use cloud-agnostic path",
			version:  "7.26.0",
			platform: "windows",
			cloud:    falcon.CloudUs2,
			want:     true,
		},
		{
			name:     "Windows 7.26.0 gov cloud should use cloud-agnostic path",
			version:  "7.26.0",
			platform: "windows",
			cloud:    falcon.CloudUsGov1,
			want:     true,
		},
		{
			name:     "Windows 7.30.8 gov cloud should use cloud-agnostic path",
			version:  "7.30.8",
			platform: "windows",
			cloud:    falcon.CloudUsGov1,
			want:     true,
		},
		{
			name:     "Windows 7.27 gov cloud should use cloud-agnostic path",
			version:  "7.27",
			platform: "windows",
			cloud:    falcon.CloudUsGov1,
			want:     true,
		},
		// Windows sensors: >= 7.19.0 and < 7.26.0 commercial cloud-agnostic, gov cloud-specific
		{
			name:     "Windows 7.25.3 commercial cloud should use cloud-agnostic path",
			version:  "7.25.3",
			platform: "windows",
			cloud:    falcon.CloudUs2,
			want:     true,
		},
		{
			name:     "Windows 7.25.3 gov cloud should use cloud-specific path",
			version:  "7.25.3",
			platform: "windows",
			cloud:    falcon.CloudUsGov1,
			want:     false,
		},
		{
			name:     "Windows 7.20.11 commercial cloud should use cloud-agnostic path",
			version:  "7.20.11",
			platform: "windows",
			cloud:    falcon.CloudUs2,
			want:     true,
		},
		{
			name:     "Windows 7.20.11 gov cloud should use cloud-specific path",
			version:  "7.20.11",
			platform: "windows",
			cloud:    falcon.CloudUsGov1,
			want:     false,
		},
		{
			name:     "Windows 7.19.0 commercial cloud should use cloud-agnostic path",
			version:  "7.19.0",
			platform: "windows",
			cloud:    falcon.CloudUs2,
			want:     true,
		},
		{
			name:     "Windows 7.19.0 gov cloud should use cloud-specific path",
			version:  "7.19.0",
			platform: "windows",
			cloud:    falcon.CloudUsGov1,
			want:     false,
		},
		// Windows sensors: < 7.19.0 all clouds cloud-specific
		{
			name:     "Windows 7.18.6 commercial cloud should use cloud-specific path",
			version:  "7.18.6",
			platform: "windows",
			cloud:    falcon.CloudUs2,
			want:     false,
		},
		{
			name:     "Windows 7.18.6 gov cloud should use cloud-specific path",
			version:  "7.18.6",
			platform: "windows",
			cloud:    falcon.CloudUsGov1,
			want:     false,
		},
		{
			name:     "Windows 6.50.2 commercial cloud should use cloud-specific path",
			version:  "6.50.2",
			platform: "windows",
			cloud:    falcon.CloudUs2,
			want:     false,
		},
		{
			name:     "Windows 6.50.2 gov cloud should use cloud-specific path",
			version:  "6.50.2",
			platform: "windows",
			cloud:    falcon.CloudUsGov1,
			want:     false,
		},
		// Invalid versions
		{
			name:     "Invalid version should return false",
			version:  "invalid",
			platform: "linux",
			cloud:    falcon.CloudUs2,
			want:     false,
		},
		{
			name:     "Empty version should return false",
			version:  "",
			platform: "linux",
			cloud:    falcon.CloudUs2,
			want:     false,
		},
		// Unsupported platforms
		{
			name:     "Unsupported platform should return false",
			version:  "7.30.0",
			platform: "macos",
			cloud:    falcon.CloudUs2,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldUseCloudAgnosticPath(tt.version, tt.platform, tt.cloud)
			assert.Equal(t, tt.want, got)
		})
	}
}
