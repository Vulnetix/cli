package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/internal/update"
)

var versionShort bool

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of Vulnetix CLI",
	Run: func(cmd *cobra.Command, args []string) {
		if versionShort {
			fmt.Println(version)
			return
		}

		fmt.Printf("Vulnetix CLI v%s\n", version)
		fmt.Printf("  Commit:     %s\n", commit)
		fmt.Printf("  Built:      %s\n", buildDate)
		fmt.Printf("  Go version: %s\n", runtime.Version())
		fmt.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)

		// Check for updates
		release, err := update.CheckLatest()
		if err != nil {
			return // silently skip update check on error
		}
		latest, err := update.ParseVersion(release.TagName)
		if err != nil {
			return
		}
		current, err := update.ParseVersion(version)
		if err != nil {
			return
		}
		if latest.IsNewerThan(current) {
			fmt.Printf("\nA new version is available: v%s → v%s\n", current, latest)
			fmt.Println("Run 'vulnetix update' to update.")
		}
	},
}

func init() {
	versionCmd.Flags().BoolVar(&versionShort, "short", false, "Print only the version number")
	rootCmd.AddCommand(versionCmd)
}
