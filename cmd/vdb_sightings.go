package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var sightingsOutput string

var sightingsCmd = &cobra.Command{
	Use:   "sightings <CVE-ID>",
	Short: "Merged in-the-wild observation timeline for a CVE",
	Long: `Merged chronological timeline of in-the-wild observations across:

  - Shadowserver honeypot daily counts
  - VulnCheck reportedExploitation URLs
  - CVEAiInWildExploitation (AI-discovered events)

Headlines: firstObservation, lastObservation, daysSinceLastSeen.

  vulnetix vdb sightings CVE-2024-12847
  vulnetix vdb sightings CVE-2021-44228 -o sightings.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cveID := strings.ToUpper(strings.TrimSpace(args[0]))
		client := newVDBClient()
		client.APIVersion = "/v2"
		resp, err := client.V2VulnSightings(cveID)
		if err != nil {
			return fmt.Errorf("sightings: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("sightings", cveID)
		body, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return err
		}
		return writeOutput(cmd, body, sightingsOutput)
	},
}

func init() {
	sightingsCmd.Flags().StringVarP(&sightingsOutput, "output", "o", "", "Write JSON to this file")
	vdbCmd.AddCommand(sightingsCmd)
}
