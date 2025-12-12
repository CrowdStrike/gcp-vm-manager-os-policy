package sensor

import (
	"testing"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/stretchr/testify/assert"
)

func TestSensor_determineBucketPath(t *testing.T) {
	tests := []struct {
		name          string
		sensor        Sensor
		sensorVersion string
		expectedPath  string
	}{
		{
			name: "Linux 7.28.0 removes cloud from path",
			sensor: Sensor{
				Platform:     "linux",
				Cloud:        falcon.CloudUs2,
				BucketPrefix: "crowdstrike/falcon/us-2/linux/rhel/8",
			},
			sensorVersion: "7.28.0",
			expectedPath:  "crowdstrike/falcon/linux/rhel/8",
		},
		{
			name: "Linux 7.29.15 removes cloud from path",
			sensor: Sensor{
				Platform:     "linux",
				Cloud:        falcon.CloudUs1,
				BucketPrefix: "crowdstrike/falcon/us-1/linux/ubuntu",
			},
			sensorVersion: "7.29.15",
			expectedPath:  "crowdstrike/falcon/linux/ubuntu",
		},
		{
			name: "Linux 7.27.0 keeps cloud in path",
			sensor: Sensor{
				Platform:     "linux",
				Cloud:        falcon.CloudUs2,
				BucketPrefix: "crowdstrike/falcon/us-2/linux/rhel/8",
			},
			sensorVersion: "7.27.0",
			expectedPath:  "crowdstrike/falcon/us-2/linux/rhel/8",
		},
		{
			name: "Linux 7.20.5 gov cloud keeps cloud in path",
			sensor: Sensor{
				Platform:     "linux",
				Cloud:        falcon.CloudUsGov1,
				BucketPrefix: "crowdstrike/falcon/us-gov-1/linux/debian",
			},
			sensorVersion: "7.20.5",
			expectedPath:  "crowdstrike/falcon/us-gov-1/linux/debian",
		},
		{
			name: "Windows 7.26.0 commercial cloud removes cloud from path",
			sensor: Sensor{
				Platform:     "windows",
				Cloud:        falcon.CloudUs2,
				BucketPrefix: "crowdstrike/falcon/us-2/windows",
			},
			sensorVersion: "7.26.0",
			expectedPath:  "crowdstrike/falcon/windows",
		},
		{
			name: "Windows 7.26.0 gov cloud removes cloud from path",
			sensor: Sensor{
				Platform:     "windows",
				Cloud:        falcon.CloudUsGov1,
				BucketPrefix: "crowdstrike/falcon/us-gov-1/windows",
			},
			sensorVersion: "7.26.0",
			expectedPath:  "crowdstrike/falcon/windows",
		},
		{
			name: "Windows 7.25.3 commercial cloud removes cloud from path",
			sensor: Sensor{
				Platform:     "windows",
				Cloud:        falcon.CloudUs2,
				BucketPrefix: "crowdstrike/falcon/us-2/windows",
			},
			sensorVersion: "7.25.3",
			expectedPath:  "crowdstrike/falcon/windows",
		},
		{
			name: "Windows 7.25.3 gov cloud keeps cloud in path",
			sensor: Sensor{
				Platform:     "windows",
				Cloud:        falcon.CloudUsGov1,
				BucketPrefix: "crowdstrike/falcon/us-gov-1/windows",
			},
			sensorVersion: "7.25.3",
			expectedPath:  "crowdstrike/falcon/us-gov-1/windows",
		},
		{
			name: "Windows 7.18.6 commercial cloud keeps cloud in path",
			sensor: Sensor{
				Platform:     "windows",
				Cloud:        falcon.CloudUs2,
				BucketPrefix: "crowdstrike/falcon/us-2/windows",
			},
			sensorVersion: "7.18.6",
			expectedPath:  "crowdstrike/falcon/us-2/windows",
		},
		{
			name: "Windows 7.18.6 gov cloud keeps cloud in path",
			sensor: Sensor{
				Platform:     "windows",
				Cloud:        falcon.CloudUsGov1,
				BucketPrefix: "crowdstrike/falcon/us-gov-1/windows",
			},
			sensorVersion: "7.18.6",
			expectedPath:  "crowdstrike/falcon/us-gov-1/windows",
		},
		{
			name: "CentOS 9 path with cloud removal",
			sensor: Sensor{
				Platform:     "linux",
				Cloud:        falcon.CloudEu1,
				BucketPrefix: "crowdstrike/falcon/eu-1/linux/centos/9",
			},
			sensorVersion: "7.30.0",
			expectedPath:  "crowdstrike/falcon/linux/centos/9",
		},
		{
			name: "SLES with cloud removal",
			sensor: Sensor{
				Platform:     "linux",
				Cloud:        falcon.CloudUs1,
				BucketPrefix: "crowdstrike/falcon/us-1/linux/sles/15",
			},
			sensorVersion: "7.28.0",
			expectedPath:  "crowdstrike/falcon/linux/sles/15",
		},
		{
			name: "Path without cloud remains unchanged",
			sensor: Sensor{
				Platform:     "linux",
				Cloud:        falcon.CloudUs2,
				BucketPrefix: "crowdstrike/falcon/linux/rhel/8",
			},
			sensorVersion: "7.30.0",
			expectedPath:  "crowdstrike/falcon/linux/rhel/8",
		},
		{
			name: "Invalid version keeps original path",
			sensor: Sensor{
				Platform:     "linux",
				Cloud:        falcon.CloudUs2,
				BucketPrefix: "crowdstrike/falcon/us-2/linux/rhel/8",
			},
			sensorVersion: "invalid-version",
			expectedPath:  "crowdstrike/falcon/us-2/linux/rhel/8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version := tt.sensorVersion
			sensorResource := &models.DomainSensorInstallerV1{
				Version: &version,
			}

			got := tt.sensor.determineBucketPath(sensorResource)
			assert.Equal(t, tt.expectedPath, got)
		})
	}
}
