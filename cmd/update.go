package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/internal/update"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update Vulnetix CLI to the latest version",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Refuse early if built from source
		method := update.DetectInstallMethod(version, commit)
		if method == update.MethodSourceBuild {
			return fmt.Errorf("this binary was built from source; use 'go build' or 'just dev' to update")
		}

		// Check latest version
		release, err := update.CheckLatest()
		if err != nil {
			return err
		}

		latest, err := update.ParseVersion(release.TagName)
		if err != nil {
			return fmt.Errorf("cannot parse latest version %q: %w", release.TagName, err)
		}

		current, err := update.ParseVersion(version)
		if err != nil {
			return fmt.Errorf("cannot parse current version %q: %w", version, err)
		}

		if !latest.IsNewerThan(current) {
			fmt.Printf("Already up to date (v%s).\n", current)
			return nil
		}

		fmt.Printf("Updating v%s → v%s\n", current, latest)

		if err := update.Update(version, commit); err != nil {
			fmt.Fprintf(os.Stderr, "Update failed: %s\n", err)
			os.Exit(1)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
