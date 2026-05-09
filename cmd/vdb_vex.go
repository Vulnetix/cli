package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/pkg/vdb"
)

var (
	vexListCveIDs   []string
	vexListStatus   string
	vexListSupplier string
	vexListSince    string
	vexListLimit    int
	vexListOffset   int
	vexOutput       string
)

var vexCmd = &cobra.Command{
	Use:   "vex",
	Short: "VEX statements (vendor not_affected / fixed / under_investigation)",
	Long: `VEX (Vulnerability Exploitability eXchange) statements declared by your
organisation's uploaded VEX documents. Used during triage to deprioritise
findings the vendor has marked not_affected.

  vulnetix vdb vex get CVE-2021-44228
  vulnetix vdb vex list --status not_affected --supplier "Red Hat"`,
}

var vexGetCmd = &cobra.Command{
	Use:   "get <CVE-ID>",
	Short: "VEX statements declared for a single CVE",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cveID := strings.ToUpper(strings.TrimSpace(args[0]))
		client := newVDBClient()
		client.APIVersion = "/v2"
		resp, err := client.V2VulnVex(cveID)
		if err != nil {
			return fmt.Errorf("vex get: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("vex-get", cveID)
		body, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return err
		}
		return writeOutput(cmd, body, vexOutput)
	},
}

var vexListCmd = &cobra.Command{
	Use:   "list",
	Short: "Search VEX statements (filter by status, supplier, since)",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()
		client.APIVersion = "/v2"
		resp, err := client.V2VexSearch(vdb.VexSearchParams{
			CveIDs:   upperAll(vexListCveIDs),
			Status:   vexListStatus,
			Supplier: vexListSupplier,
			Since:    vexListSince,
			Limit:    vexListLimit,
			Offset:   vexListOffset,
		})
		if err != nil {
			return fmt.Errorf("vex list: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("vex-list", vexListStatus)
		body, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return err
		}
		return writeOutput(cmd, body, vexOutput)
	},
}

func init() {
	listFlags := vexListCmd.Flags()
	listFlags.StringSliceVar(&vexListCveIDs, "cve-id", nil, "Restrict to one or more CVE IDs (repeat)")
	listFlags.StringVar(&vexListStatus, "status", "", "VEX status (e.g. not_affected, fixed, under_investigation)")
	listFlags.StringVar(&vexListSupplier, "supplier", "", "ILIKE substring on supplier")
	listFlags.StringVar(&vexListSince, "since", "", "Only statements with timestamp >= RFC3339")
	listFlags.IntVar(&vexListLimit, "limit", 50, "Max items per page (1-200)")
	listFlags.IntVar(&vexListOffset, "offset", 0, "Pagination offset")

	for _, c := range []*cobra.Command{vexGetCmd, vexListCmd} {
		c.Flags().StringVarP(&vexOutput, "output", "o", "", "Write JSON to this file")
	}

	vexCmd.AddCommand(vexGetCmd)
	vexCmd.AddCommand(vexListCmd)
	vdbCmd.AddCommand(vexCmd)
}
