package prompt

import (
	"fmt"

	"github.com/charmbracelet/huh"
)

// validate param input
func validateParam(param string) func(string) error {
	return func(str string) error {
		if str == "" {
			return fmt.Errorf("a value is required for %s", param)
		}
		return nil
	}
}

func PromptOutputBucket() (string, error) {
	var outputBucket string
	f := huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title("Please provide the name of the GCP storage bucket where you want to stage the sensor binaries").
			Value(&outputBucket).
			Validate(validateParam("GCP storage bucket")),
	)).WithTheme(huh.ThemeBase())

	err := f.Run()
	return outputBucket, err
}

func PromptClientId() (string, error) {
	var falconClientId string
	f := huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title("Please provide your falcon client id").
			Value(&falconClientId).
			Validate(validateParam("falcon client id")),
	)).WithTheme(huh.ThemeBase())

	err := f.Run()
	return falconClientId, err
}

func PromptClientSecret() (string, error) {
	var falconClientSecret string
	f := huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title("Please provide your falcon client secret").
			Value(&falconClientSecret).
			Password(true).
			Validate(validateParam("falcon client secret")),
	)).WithTheme(huh.ThemeBase())

	err := f.Run()
	return falconClientSecret, err
}

func PromptCloud() (string, error) {
	var falconCloud string
	f := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Title("Please select your falcon cloud").
			Options(
				huh.NewOption("autodiscover", "autodiscover"),
				huh.NewOption("us-1", "us-1"),
				huh.NewOption("us-2", "us-2"),
				huh.NewOption("eu-1", "eu-1"),
				huh.NewOption("us-gov-1", "us-gov-1"),
			).
			Value(&falconCloud),
	)).WithTheme(huh.ThemeBase())

	err := f.Run()
	return falconCloud, err
}
