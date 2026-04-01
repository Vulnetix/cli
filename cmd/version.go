package cmd

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/internal/display"
	"github.com/vulnetix/cli/internal/update"
)

var versionShort bool

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of Vulnetix CLI",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := display.FromCommand(cmd)
		t := ctx.Term

		if versionShort {
			fmt.Println(version)
			return
		}

		var b strings.Builder
		b.WriteString(display.Bold(t, fmt.Sprintf("Vulnetix CLI v%s", version)) + "\n")
		b.WriteString(display.KeyValue(t, []display.KVPair{
			{Key: "Commit", Value: commit},
			{Key: "Built", Value: buildDate},
			{Key: "Go version", Value: runtime.Version()},
			{Key: "OS/Arch", Value: fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)},
		}))

		// Check for updates
		release, err := update.CheckLatest()
		if err == nil {
			latest, err := update.ParseVersion(release.TagName)
			if err == nil {
				current, err := update.ParseVersion(version)
				if err == nil && latest.IsNewerThan(current) {
					b.WriteString(fmt.Sprintf("\n\n%s v%s → v%s\n",
						display.Accent(t, "Update available:"),
						current, latest))
					b.WriteString(display.Muted(t, "Run 'vulnetix update' to update."))
				}
			}
		}

		ctx.Logger.Result(b.String())
	},
}

func init() {
	versionCmd.Flags().BoolVar(&versionShort, "short", false, "Print only the version number")
	rootCmd.AddCommand(versionCmd)
}
