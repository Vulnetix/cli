package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/pkg/auth"
)

var noBanner bool

func init() {
	rootCmd.PersistentFlags().BoolVar(&noBanner, "no-banner", false, "Suppress the Vulnetix startup banner")
}

func printBanner(cmd *cobra.Command) {
	if noBanner || silent || os.Getenv("CI") == "true" || os.Getenv("DO_NOT_TRACK") == "1" {
		return
	}

	dc := display.FromCommand(cmd)
	if dc == nil || dc.Term == nil {
		return
	}
	t := dc.Term

	banner := []string{
		display.Teal(t, `$$\    $$\           $$\                      $$\     $$\           `),
		display.Teal(t, `$$ |   $$ |          $$ |                     $$ |    \__|          `),
		display.Teal(t, `$$ |   $$ |$$\   $$\ $$ |$$$$$$$\   $$$$$\ $$$$$$\   $$\ $$\   $$\ `),
		display.Teal(t, `\$$\  $$  |$$ |  $$ |$$ |$$  __$$\ $$  __$$\\_$$  _|  $$ |\$$\ $$  |`),
		display.Teal(t, ` \$$\$$  / $$ |  $$ |$$ |$$ |  $$ |$$$$$$$$ | $$ |    $$ | \$$$$  / `),
		display.Teal(t, `  \$$$  /  $$ |  $$ |$$ |$$ |  $$ |$$   ____| $$ |$$\ $$ | $$  $$<  `),
		display.Teal(t, `   \$  /   \$$$$$$  |$$ |$$ |  $$ |\$$$$$$$\  \$$$$  |$$ |$$  /\$$\ `),
		display.Teal(t, `    \_/     \______/ \__|\__|  \__| \_______|  \____/ \__|\__/  \__|`),
	}

	for _, line := range banner {
		fmt.Fprintln(os.Stderr, " "+line)
	}
	fmt.Fprintln(os.Stderr)

	fmt.Fprintf(os.Stderr, "  %s %s\n", display.Muted(t, "Version:"), display.Bold(t, version))
	fmt.Fprintf(os.Stderr, "  %s %s\n", display.Muted(t, "Build:  "), display.Bold(t, commit))

	fmt.Fprintln(os.Stderr, display.Muted(t, "  ──────────────────────────────────────────────────────"))

	authSrc := auth.CredentialSource()
	var authText string
	if authSrc == "none" {
		authText = fmt.Sprintf("%s %s", display.WarningMark(t), display.Accent(t, "Community (Unauthenticated)"))
	} else {
		authText = fmt.Sprintf("%s %s", display.CheckMark(t), display.Success(t, "Authenticated"))
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", display.Muted(t, "Auth:   "), authText)

	var apiText string
	if authSrc != "none" {
		apiText = fmt.Sprintf("%s %s", display.CheckMark(t), display.Success(t, "Ready"))
	} else {
		apiText = fmt.Sprintf("%s %s", display.Muted(t, "i"), display.Muted(t, "Community fallback available"))
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", display.Muted(t, "API:    "), apiText)

	var fwText string
	if home, err := os.UserHomeDir(); err == nil {
		groups := groupEcosystems(home, auth.PackageFirewallHost)
		if len(groups.Configured) > 0 {
			formattedEcos := make([]string, len(groups.Configured))
			for i, e := range groups.Configured {
				formattedEcos[i] = display.Teal(t, e.Ecosystem.DisplayName)
			}
			fwText = fmt.Sprintf("%s %s", display.CheckMark(t), display.Success(t, strings.Join(formattedEcos, display.Muted(t, ", "))))
		} else {
			fwText = fmt.Sprintf("%s %s", display.Muted(t, "i"), display.Muted(t, "No ecosystems configured"))
		}
	} else {
		fwText = fmt.Sprintf("%s %s", display.Muted(t, "i"), display.Muted(t, "Ecosystem status unavailable"))
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", display.Muted(t, "Firewall:"), fwText)

	fmt.Fprintln(os.Stderr)
}
