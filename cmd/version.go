package cmd

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/update"
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
		b.WriteString(display.Bold(t, "Vulnetix CLI "+displayVersion()) + "\n")
		b.WriteString(display.KeyValue(t, []display.KVPair{
			{Key: "Commit", Value: commit},
			{Key: "Built", Value: buildDate},
			{Key: "Go version", Value: runtime.Version()},
			{Key: "OS/Arch", Value: fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)},
			{Key: "", Value: ""},
			{Key: "github.com/vulnetix/malscan-engine", Value: moduleVersion("github.com/vulnetix/malscan-engine")},
			{Key: "github.com/Vulnetix/vdb-cyclonedx", Value: moduleVersion("github.com/Vulnetix/vdb-cyclonedx")},
			{Key: "github.com/open-policy-agent/opa", Value: moduleVersion("github.com/open-policy-agent/opa")},
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

func moduleVersion(path string) string {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}

	return moduleVersionFromDeps(path, buildInfo.Deps)
}

func moduleVersionFromDeps(path string, deps []*debug.Module) string {
	for _, dep := range deps {
		if dep.Path != path {
			continue
		}
		if dep.Replace != nil && dep.Replace.Version != "" {
			return dep.Replace.Version
		}
		if dep.Version != "" {
			return dep.Version
		}
		return "unknown"
	}

	return "unknown"
}

func init() {
	versionCmd.Flags().BoolVar(&versionShort, "short", false, "Print only the version number")
	rootCmd.AddCommand(versionCmd)
}

// displayVersion is the version as the banner prints it: exactly one leading
// "v". Release builds inject the tag ("v3.115.5") and dev builds a bare
// semver, so prefixing unconditionally printed "vv3.115.5" for every release.
func displayVersion() string {
	return "v" + strings.TrimPrefix(version, "v")
}
