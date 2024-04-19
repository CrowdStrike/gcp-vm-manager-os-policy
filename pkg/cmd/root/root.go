package root

import (
	"os"

	"github.com/MakeNowJust/heredoc"
	"github.com/crowdstrike/gcp-os-policy/pkg/cmd/setup"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cs-policy <command> [flags]",
	Short: "cs-policy CLI",
	Example: heredoc.Doc(`
    $ cs-policy setup --help
    `),
}

// Execute adds all child commands to the root cs-policy setup and sets flags appropriately.
func Execute() {
	rootCmd.AddCommand(setup.NewSetupCmd())

	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
