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
	Long: `Fetch and triage vulnerability alerts from GitHub security tools
with integrated remediation intelligence from the Vulnetix Vulnerability Database.

Supported providers:
  - github      All GitHub security alerts (Dependabot + CodeQL + Secret Scanning)
  - dependabot  Dependabot alerts only
  - codeql      Code Scanning (CodeQL) alerts only
  - secrets     Secret Scanning alerts only
`,
}
