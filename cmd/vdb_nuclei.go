package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var (
	nucleiFormat string
	nucleiFirst  bool
	nucleiOutput string
)

var nucleiCmd = &cobra.Command{
	Use:   "nuclei",
	Short: "Nuclei templates referencing a CVE",
	Long: `Look up ProjectDiscovery Nuclei template paths attached to a CVE.

JSON listing (default):
  vulnetix vdb nuclei get CVE-2021-44228

YAML body of every template, concatenated (suitable for nuclei -t -):
  vulnetix vdb nuclei get CVE-2021-44228 --format yaml

YAML body of just the first template:
  vulnetix vdb nuclei get CVE-2021-44228 --format yaml --first | nuclei -t - -u https://target`,
}

var nucleiGetCmd = &cobra.Command{
	Use:   "get <CVE-ID>",
	Short: "List or fetch nuclei template bodies for a CVE",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cveID := strings.ToUpper(strings.TrimSpace(args[0]))
		client := newVDBClient()
		client.APIVersion = "/v2"

		if strings.ToLower(nucleiFormat) == "yaml" {
			body, err := client.V2VulnNucleiYAML(cveID, nucleiFirst)
			if err != nil {
				return fmt.Errorf("nuclei get yaml: %w", err)
			}
			printRateLimit(client)
			recordVDBQuery("nuclei-yaml", cveID)
			return writeOutput(cmd, body, nucleiOutput)
		}

		resp, err := client.V2VulnNuclei(cveID)
		if err != nil {
			return fmt.Errorf("nuclei get: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("nuclei-get", cveID)
		body, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return err
		}
		return writeOutput(cmd, body, nucleiOutput)
	},
}

func init() {
	nucleiGetCmd.Flags().StringVar(&nucleiFormat, "format", "json", "Output format: json | yaml")
	nucleiGetCmd.Flags().BoolVar(&nucleiFirst, "first", false, "(yaml) Return only the first template body")
	nucleiGetCmd.Flags().StringVarP(&nucleiOutput, "output", "o", "", "Write to this file")

	nucleiCmd.AddCommand(nucleiGetCmd)
	vdbCmd.AddCommand(nucleiCmd)
}
