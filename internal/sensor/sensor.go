package sensor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"cloud.google.com/go/storage"
	"github.com/crowdstrike/gcp-os-policy/internal/progress"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

type Sensor struct {
	OsShortName    string
	OsVersion      string
	Filter         string
	BucketPrefix   string
	FullPath       string
	ProgressWriter *progress.ProgressWriter
	SensorInfo     models.DomainSensorInstallerV1
	Generation     int64
}

// StreamToBucket will download and upload to a gcp storage bucket at the same time.
func (s *Sensor) StreamToBucket(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	storageClient *storage.Client,
	bucket string,
) error {

	// using limit, offset, and sort we can grab the n-1 version
	var limit int64
	var offset int64
	var sort string

	limit = 1
	sort = "version"
	offset = 1

	query, err := client.SensorDownload.GetCombinedSensorInstallersByQuery(
		&sensor_download.GetCombinedSensorInstallersByQueryParams{
			Filter:  &s.Filter,
			Limit:   &limit,
			Sort:    &sort,
			Offset:  &offset,
			Context: ctx,
		},
	)

	if err != nil {
		return err
	}

	if len(query.Payload.Resources) == 0 {
		return fmt.Errorf("no sensors found matching filter: %s", s.Filter)
	}

	sensorResource := query.Payload.Resources[0]
	s.ProgressWriter = progress.NewProgressWriter()
	s.SensorInfo = *sensorResource

	o := storageClient.Bucket(bucket).
		Object(filepath.Join(s.BucketPrefix, *sensorResource.Version, *sensorResource.Name))

	// check if a sensor already exists in the bucket
	attrs, err := o.Attrs(ctx)
	if err == nil {
		s.FullPath = fmt.Sprintf("%s/%s", attrs.Bucket, attrs.Name)
		s.Generation = attrs.Generation
		return nil
	} else {
		if !errors.Is(storage.ErrObjectNotExist, err) {
			return err
		}
	}

	s.ProgressWriter.SetTotal(int64(*sensorResource.FileSize))
	wc := o.NewWriter(ctx)

	_, err = client.SensorDownload.DownloadSensorInstallerByID(
		&sensor_download.DownloadSensorInstallerByIDParams{
			ID:      *sensorResource.Sha256,
			Context: ctx,
		},
		io.MultiWriter(wc, s.ProgressWriter),
	)

	if err != nil {
		return err
	}

	if err := wc.Close(); err != nil {
		return err
	}

	attrs, err = o.Attrs(ctx)
	if err != nil {
		return err
	}

	s.FullPath = fmt.Sprintf("%s/%s", attrs.Bucket, attrs.Name)
	s.Generation = attrs.Generation

	return nil
}
