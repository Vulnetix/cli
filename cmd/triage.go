package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(triageCmd)
}

var triageCmd = &cobra.Command{
	Use:   "triage",
	Short: "Triage vulnerability alerts from multiple providers",
	Long: `Fetch and triage vulnerability alerts from multiple providers (GitHub Dependabot, etc.)
with integrated remediation intelligence from the Vulnetix Vulnerability Database.

Supported providers:
  -  github (Dependabot alerts via gh CLI)
`,
}
