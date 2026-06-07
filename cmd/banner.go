package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/packagefirewall"
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

	apiText := display.Muted(t, "Ready (use 'vulnetix info' for full healthcheck)")
	if authSrc != "none" {
		apiText = fmt.Sprintf("%s %s", display.CheckMark(t), display.Success(t, "Ready"))
	} else {
		apiText = fmt.Sprintf("%s %s", display.Muted(t, "ℹ"), display.Muted(t, "Community fallback available"))
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", display.Muted(t, "API:    "), apiText)

	home, _ := os.UserHomeDir()
	var activeEcos []string
	for _, eco := range packagefirewall.All() {
		paths := packagefirewall.ConfigPaths(eco, home)
		for _, p := range paths {
			if strings.HasPrefix(p, "~") {
				p = filepath.Join(home, p[1:])
			}
			if _, err := os.Stat(p); err == nil {
				activeEcos = append(activeEcos, eco.DisplayName)
				break
			}
		}
	}

	var fwText string
	if len(activeEcos) > 0 {
		formattedEcos := make([]string, len(activeEcos))
		for i, e := range activeEcos {
			formattedEcos[i] = display.Teal(t, e)
		}
		fwText = fmt.Sprintf("%s %s", display.CheckMark(t), display.Success(t, strings.Join(formattedEcos, display.Muted(t, ", "))))
	} else {
		fwText = fmt.Sprintf("%s %s", display.Muted(t, "ℹ"), display.Muted(t, "No ecosystems configured"))
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", display.Muted(t, "Firewall:"), fwText)

	fmt.Fprintln(os.Stderr)
}
