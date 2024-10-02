package create

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"cloud.google.com/go/storage"
	"github.com/MakeNowJust/heredoc"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/crowdstrike/gcp-os-policy/internal/errorsutil"
	"github.com/crowdstrike/gcp-os-policy/internal/falconutil"
	"github.com/crowdstrike/gcp-os-policy/internal/policy"
	"github.com/crowdstrike/gcp-os-policy/internal/prompt"
	"github.com/crowdstrike/gcp-os-policy/internal/sensor"
	"github.com/crowdstrike/gcp-os-policy/internal/tui"
	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

var falconClientId string
var falconClientSecret string
var falconCloud string
var falconCid string
var linuxInstallParams string
var windowsInstallParams string
var storageBucket string
var outputDir string
var zones []string
var skipWait bool
var inclusionLabels []string
var exclusionLabels []string

// createCmd represents the base cs-policy create when called without any ubcommands
var createCmd = &cobra.Command{
	Use:   "create [flags]",
	Short: "Create GCP OS Policy Assignments for Falcon Sensor deployment",
	Long: `Create GCP OS Policy Assignments for Falcon Sensor deployment 

  The following is done on behalf of the user:
    - Download the n-1 version of the falcon sensor
    - Upload the falcon sensor binaries to the gcp cloud storage bucket of choice
    - Modify the falcon sensor gcp os policy to use the binaries in cloud storage bucket
    - Create OS Policy Assignments in the targeted zones`,
	Example: heredoc.Doc(`
    Target all VMs in the us-central1-a and us-central-b zones
    $ cs-policy create --zones=us-central1-a,us-central-b --buckt=my-bucket

    Target all VMs in the us-central1-a zone with custom install parameters
    $ cs-policy create --bucket example-bucket --zone us-central1-a --linux-install-params='--tags="Washington/DC_USA,Production" --aph=proxy.example.com --app=8080' --windows-install-params='GROUPING_TAGS="Washington/DC_USA,Production" APP_PROXYNAME=proxy.example.com APP_PROXYPORT=8080'
    `),
	Args: cobra.ExactArgs(0),
	Run: func(_ *cobra.Command, _ []string) {
		var err error

		// Start output with new line.
		fmt.Println("")

		if falconCloud == "" {
			falconCloud, err = prompt.PromptCloud()
			if err != nil {
				if errors.Is(huh.ErrUserAborted, err) {
					fmt.Println("User aborted, gracefully quiting...")
					return
				}
				fmt.Println(err)
				return
			}
		}

		cloud, err := falcon.CloudValidate(falconCloud)

		if err != nil {
			fmt.Println(
				errorsutil.DefaultError(
					fmt.Sprintf("Unable to validate %s as falcon cloud.", falconCloud),
					err,
				),
			)
			return
		}

		if falconClientId == "" {
			falconClientId, err = prompt.PromptClientId()
			if err != nil {
				if errors.Is(huh.ErrUserAborted, err) {
					fmt.Println("User aborted, gracefully quiting...")
					return
				}
				fmt.Println(err)
				return
			}
		}

		if falconClientSecret == "" {
			falconClientSecret, err = prompt.PromptClientSecret()
			if err != nil {
				if errors.Is(huh.ErrUserAborted, err) {
					fmt.Println("User aborted, gracefully quiting...")
					return
				}
				fmt.Println(err)
				return
			}
		}

		if storageBucket == "" {
			storageBucket, err = prompt.PromptOutputBucket()
			if err != nil {
				if errors.Is(huh.ErrUserAborted, err) {
					fmt.Println("User aborted, gracefully quiting...")
					return
				}
				fmt.Println(err)
				return
			}
		}

		ac := falcon.ApiConfig{
			ClientId:     falconClientId,
			ClientSecret: falconClientSecret,
			Cloud:        cloud,
			Context:      context.Background(),
		}

		client, err := falcon.NewClient(&ac)

		if err != nil {
			fmt.Println(
				errorsutil.DefaultError("Unexpected error while creating falcon client.", err),
			)
			return
		}

		if falconCid == "" {
			fmt.Println("No cid provided, grabbing cid...")

			cid, err := falconutil.CID(client)
			if err != nil {
				fmt.Println(
					errorsutil.DefaultError("Unexpected error while grabbing cid.", err),
				)
				return
			}

			fmt.Printf("Using cid: %s\n", cid)
			falconCid = cid
		}

		targetSensors := []sensor.Sensor{
			{
				Filter:       "os:'*RHEL*'+os_version:'7'+platform:'linux'",
				OsShortName:  "rhel",
				OsVersion:    "7*",
				BucketPrefix: fmt.Sprintf("crowdstrike/falcon/%s/linux/rhel/7", ac.Cloud.String()),
			},
			{
				Filter:       "os:'*RHEL*'+os_version:'8'+platform:'linux'",
				OsShortName:  "rhel",
				OsVersion:    "8*",
				BucketPrefix: fmt.Sprintf("crowdstrike/falcon/%s/linux/rhel/8", ac.Cloud.String()),
			},
			{
				Filter:       "os:'*RHEL*'+os_version:'9'+platform:'linux'",
				OsShortName:  "rhel",
				OsVersion:    "9*",
				BucketPrefix: fmt.Sprintf("crowdstrike/falcon/%s/linux/rhel/9", ac.Cloud.String()),
			},
			{
				Filter:      "os:'*CentOS*'+os_version:'7'+platform:'linux'",
				OsShortName: "centos",
				OsVersion:   "7*",
				BucketPrefix: fmt.Sprintf(
					"crowdstrike/falcon/%s/linux/centos/7",
					ac.Cloud.String(),
				),
			},
			{
				Filter:      "os:'*CentOS*'+os_version:'8'+platform:'linux'",
				OsShortName: "centos",
				OsVersion:   "8*",
				BucketPrefix: fmt.Sprintf(
					"crowdstrike/falcon/%s/linux/centos/8",
					ac.Cloud.String(),
				),
			},
			{
				Filter:      "os:'*SLES*'+os_version:'12'+platform:'linux'",
				OsShortName: "sles",
				OsVersion:   "12*",
				BucketPrefix: fmt.Sprintf(
					"crowdstrike/falcon/%s/linux/sles/12",
					ac.Cloud.String(),
				),
			},
			{
				Filter:      "os:'*SLES*'+os_version:'15'+platform:'linux'",
				OsShortName: "sles",
				OsVersion:   "15*",
				BucketPrefix: fmt.Sprintf(
					"crowdstrike/falcon/%s/linux/sles/15",
					ac.Cloud.String(),
				),
			},
			{
				Filter:      "os:'*Ubuntu*'+os_version:'*16/18/20/22*'+os_version:!'*arm64*'+os_version:!~'zLinux'+platform:'linux'",
				OsShortName: "ubuntu",
				BucketPrefix: fmt.Sprintf(
					"crowdstrike/falcon/%s/linux/ubuntu",
					ac.Cloud.String(),
				),
			},
			{
				Filter:      "os:'Debian'+os_version:'*9/10/11*'+os_version:!'*arm64*'+platform:'linux'",
				OsShortName: "debian",
				BucketPrefix: fmt.Sprintf(
					"crowdstrike/falcon/%s/linux/debian",
					ac.Cloud.String(),
				),
			},
			{
				Filter:      "os:'Windows'+platform:'windows'",
				OsShortName: "windows",
				BucketPrefix: fmt.Sprintf(
					"crowdstrike/falcon/%s/windows",
					ac.Cloud.String(),
				),
			},
		}

		var storageSyncModel tui.StorageSyncModel
		var sensors []*sensor.Sensor

		storageClient, err := storage.NewClient(context.Background())

		if err != nil {
			fmt.Println(
				errorsutil.DefaultError("Unexpected error while creating gcp storage client.", err),
			)
			return
		}

		eg, egCtx := errgroup.WithContext(context.Background())
		for _, s := range targetSensors {
			s := s
			eg.Go(func() error {
				return s.StreamToBucket(egCtx, client, storageClient, storageBucket)
			})

			sensors = append(sensors, &s)
		}

		storageSyncModel.Sensors = sensors

		p := tea.NewProgram(storageSyncModel)
		go func() {
			p.Run()
		}()

		err = eg.Wait()
		if err != nil {
			p.Quit()
			p.Wait()
			fmt.Println(
				errorsutil.DefaultError(
					fmt.Sprintf(
						"An error occurred while downloading and uploading sensor binaries to bucket(%s).",
						storageBucket,
					),
					err,
				),
			)
			return
		}

		p.Wait()

		fmt.Print("Download and upload complete...\n\n")
		fmt.Println("Generating GCP OS Policy template...")

		policy := policy.NewPolicy(
			falconCid,
			linuxInstallParams,
			windowsInstallParams,
			sensors,
			inclusionLabels,
			exclusionLabels,
		)

		policyFilePath := filepath.Join(outputDir, "template.json")
		policyFile, err := os.Create(policyFilePath)

		if err != nil {
			fmt.Println(
				errorsutil.DefaultError(
					fmt.Sprintf(
						"Unexpected error while creating template file (%s)",
						policyFilePath,
					),
					err,
				),
			)
			return
		}

		err = policy.GeneratePolicy(policyFile)
		if err != nil {
			fmt.Println(
				errorsutil.DefaultError(fmt.Sprintf(
					"Unexpected error while creating template file (%s)",
					policyFilePath,
				),
					err,
				),
			)
			return
		}

		fmt.Printf("GCP OS Policy template succesfully generated (%s)\n\n", policyFilePath)

		err = processZones(policyFilePath)

		if err != nil {
			fmt.Println(
				errorsutil.DefaultError(
					fmt.Sprint("An error occurred while creating a GCP OS Policy Assignment"),
					err,
				),
			)
			return
		}

		fmt.Println("Policy Assignments created succesfully.")
	},
}

func NewCreateCmd() *cobra.Command {
	return createCmd
}

// processZones handles the logic to create os policy assignments in each gcp compute zone
func processZones(policyFilePath string) error {
	policyModel := tui.NewPolicyModel()
	var assignments []*policy.Assignment

	// sort alphabetically
	sort.Slice(zones, func(i, j int) bool {
		return zones[i] < zones[j]
	})

	eg, egCtx := errgroup.WithContext(context.Background())
	for _, z := range zones {
		z := z
		a := policy.Assignment{
			Zone:               z,
			PolicyTemplatePath: policyFilePath,
			SkipWait:           skipWait,
		}
		eg.Go(func() error {
			return a.RollOut(egCtx)
		})

		assignments = append(assignments, &a)
	}

	policyModel.Assignments = assignments
	p := tea.NewProgram(policyModel)

	fmt.Println("Creating GCP OS Policy Assignments...")

	go func() {
		p.Run()
	}()

	err := eg.Wait()
	if err != nil {
		p.Quit()
		p.Wait()
		return err
	}
	p.Wait()

	return nil
}

func init() {
	dir, _ := os.Getwd()
	createCmd.PersistentFlags().
		StringVar(&falconClientId, "falcon-client-id", "", "Falcon API Client Id. Can also bet set by the FALCON_CLIENT_ID environment variable")
	createCmd.PersistentFlags().
		StringVar(&falconClientSecret, "falcon-client-secret", "", "Falcon API Client Secret. Can also bet set by the FALCON_CLIENT_SECRET environment variable")
	createCmd.PersistentFlags().
		StringVar(&falconCloud, "falcon-cloud", "", "Falcon Cloud one of autodiscover, us-1, us-2, eu-1, us-gov-1. Can also bet set by the FALCON_CLOUD environment variable")
	createCmd.Flags().
		StringVar(&falconCid, "falcon-cid", "", "Falcon CID to use on install. Can also bet set by the FALCON_CID environment variable. Will be pulled from the api if not provided")
	createCmd.Flags().
		StringVar(&linuxInstallParams, "linux-install-params", "", "The parameters to pass at install time on Linux machines (excluding CID)")
	createCmd.Flags().
		StringVar(&windowsInstallParams, "windows-install-params", "", "The parameters to pass at install time on Windows machines (excluding CID)")
	createCmd.Flags().
		StringVar(&storageBucket, "bucket", "", "GCP cloud storage bucket to upload sensor binaries")
	createCmd.Flags().
		StringVar(&outputDir, "output-dir", dir, "GCP OS Policy template output directory")
	createCmd.Flags().StringSliceVar(&zones, "zones", []string{}, "GCP compute zones to deploy to")
	createCmd.Flags().
		BoolVar(&skipWait, "skip-wait", false, "Skip waiting for the rollout of GCP OS Policy Assignments to complete")
	// rootCmd.Flags().
	// 	StringArrayVar(&inclusionLabels, "include-labelset", []string{}, "A comma seperated list of labels. In the format of labelName:labelValue. Matches only if a VM has all the labels in the labelset. Example: Label:Value,Env:Prod")
	// rootCmd.Flags().
	// 	StringArrayVar(&exclusionLabels, "exclude-labelset", []string{}, "A comma seperated list of labels. In the format of labelName:labelValue. Matches only if a VM has none of the labels in the labelset. Example: Label:Value,Env:Prod")
	createCmd.MarkFlagRequired("zones")

	if falconClientId == "" {
		falconClientId = os.Getenv("FALCON_CLIENT_ID")
	}

	if falconClientSecret == "" {
		falconClientSecret = os.Getenv("FALCON_CLIENT_SECRET")
	}

	if falconCloud == "" {
		falconCloud = os.Getenv("FALCON_CLOUD")
	}

	if falconCid == "" {
		falconCid = os.Getenv("FALCON_CID")
	}
}
