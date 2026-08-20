package cmd

import (
	"github.com/spf13/cobra"
)

// ─────────────────────────────────────────────────────────────────────────
// config_jail.go — `vulnetix config get jail` and `config set jail`.
//
// These DELEGATE to the same constructors the `jail` command tree uses; they do
// not reimplement anything. A *cobra.Command cannot live in two trees, so each
// parent gets its own instance built by the same function — the arrangement
// `config set ai-firewall` already uses.
//
// Both spellings exist because the two audiences look in different places: an
// operator setting up an organisation reaches for `config`, and somebody
// debugging a red pipeline reaches for the command that failed.
// ─────────────────────────────────────────────────────────────────────────

func newConfigGetJailCommand() *cobra.Command {
	cmd := newJailListCommand()
	cmd.Use = "jail"
	cmd.Short = "Show the jail policy in effect for this repository"
	return cmd
}

func newConfigSetJailCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jail",
		Short: "Manage jail exemptions for this repository",
		Long: `Manage the organisation's jail policy from the CLI.

Rules and thresholds are authored in the Vulnetix console, where they can be
reviewed and versioned. What the CLI offers here is the part a pipeline needs at
the moment it goes red: a time-boxed exemption, with a reason recorded against
whoever approved it.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error { return c.Help() },
	}
	cmd.AddCommand(newJailExemptCommand())
	return cmd
}
