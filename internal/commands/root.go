package commands

import (
	"github.com/ppiankov/ecrspectre/internal/logging"
	"github.com/spf13/cobra"
)

var (
	verbose bool
	version string
	commit  string
	date    string
)

var rootCmd = &cobra.Command{
	Use:   "ecrspectre",
	Short: "ecrspectre — container registry waste auditor",
	Long: `ecrspectre finds stale, untagged, and bloated container images in AWS ECR
and GCP Artifact Registry that accumulate storage costs silently.

Each finding includes an estimated monthly waste in USD.`,
	PersistentPreRun: func(_ *cobra.Command, _ []string) {
		logging.Init(verbose)
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command with injected build info.
func Execute(v, c, d string) error {
	version = v
	commit = c
	date = d
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	rootCmd.AddCommand(awsCmd)
	rootCmd.AddCommand(gcpCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(versionCmd)
}
