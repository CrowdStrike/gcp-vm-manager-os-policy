package falconutil

import (
	"context"
	"errors"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
)

func Cid(client *client.CrowdStrikeAPISpecification) (string, error) {
	resp, err := client.SensorDownload.GetSensorInstallersCCIDByQuery(
		&sensor_download.GetSensorInstallersCCIDByQueryParams{
			Context: context.Background(),
		},
	)

	if err != nil {
		return "", err
	}

	if len(resp.Payload.Resources) == 0 {
		return "", errors.New(
			fmt.Sprintf("Unexpected payload response. No resources found: %v", resp.Payload),
		)
	}

	return resp.Payload.Resources[0], nil
}
