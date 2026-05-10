package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/pkg/vdb"
)

var (
	triageMinEpss           float64
	triageMinEpssPercentile float64
	triageMinCess           float64
	triageMinCvss           float64
	vdbTriageSeverity          string
	triageInKev             string
	triageKevSources        []string
	triageCWEs              []string
	triageVendor            string
	triageProduct           string
	triageSince             string
	triageDays              int
	triageSort              string
	triageLimit             int
	triageOffset            int
	vdbTriageFormat            string
	triageOutput            string
)

var vdbTriageCmd = &cobra.Command{
	Use:   "triage",
	Short: "Score-driven triage feed (the daily SOC pull)",
	Long: `Combined filter across EPSS, CESS, CVSS, severity, KEV membership, and
publication date. Designed to answer 'what became actionable since
yesterday?' in one query.

Daily critical-and-exploited pull:
  vulnetix vdb triage --min-epss 0.7 --in-kev --severity high --limit 50

Recently published, critical, no fix yet (sort by publication):
  vulnetix vdb triage --min-cvss 9.0 --since 2026-05-01T00:00:00Z --sort published

KEV due-date sweep — what's overdue?:
  vulnetix vdb triage --in-kev --sort kev-due --limit 100

CSV for ticketing import:
  vulnetix vdb triage --min-epss 0.5 --severity high --format csv -o triage.csv`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()
		client.APIVersion = "/v2"
		params := vdb.TriageParams{
			Severity:   vdbTriageSeverity,
			InKev:      triageInKev,
			KevSources: triageKevSources,
			CWEs:       triageCWEs,
			Vendor:     triageVendor,
			Product:    triageProduct,
			Since:      triageSince,
			WindowDays: triageDays,
			Sort:       triageSort,
			Limit:      triageLimit,
			Offset:     triageOffset,
		}
		if cmd.Flags().Changed("min-epss") {
			v := triageMinEpss
			params.MinEpss = &v
		}
		if cmd.Flags().Changed("min-epss-percentile") {
			v := triageMinEpssPercentile
			params.MinEpssPercentile = &v
		}
		if cmd.Flags().Changed("min-cess") {
			v := triageMinCess
			params.MinCess = &v
		}
		if cmd.Flags().Changed("min-cvss") {
			v := triageMinCvss
			params.MinCvss = &v
		}
		resp, err := client.V2Triage(params)
		if err != nil {
			return fmt.Errorf("triage: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("triage", triageSort)

		switch strings.ToLower(strings.TrimSpace(vdbTriageFormat)) {
		case "csv":
			return emitTriageCSV(cmd, resp)
		default:
			body, err := json.MarshalIndent(resp, "", "  ")
			if err != nil {
				return err
			}
			return writeOutput(cmd, body, triageOutput)
		}
	},
}

func emitTriageCSV(cmd *cobra.Command, resp map[string]interface{}) error {
	items, _ := resp["items"].([]any)
	w := csv.NewWriter(cmd.OutOrStdout())
	defer w.Flush()
	_ = w.Write([]string{"cveId", "source", "severity", "cvss", "epss", "epssPercentile", "cess", "kevSource", "kevDue", "vendor", "product", "title"})
	for _, raw := range items {
		rec, _ := raw.(map[string]any)
		if rec == nil {
			continue
		}
		cvss, _ := rec["cvss"].(map[string]any)
		epss, _ := rec["epss"].(map[string]any)
		cess, _ := rec["cess"].(map[string]any)
		kev, _ := rec["kev"].(map[string]any)
		var kevSrc, kevDue string
		if kev != nil {
			kevSrc = str(kev["source"])
			kevDue = str(kev["dueDate"])
		}
		_ = w.Write([]string{
			str(rec["cveId"]), str(rec["source"]),
			str(cvss["severity"]), str(cvss["baseScore"]),
			str(epss["score"]), str(epss["percentile"]),
			str(cess["score"]),
			kevSrc, kevDue,
			str(rec["vendor"]), str(rec["product"]),
			str(rec["title"]),
		})
	}
	return nil
}

func init() {
	flags := vdbTriageCmd.Flags()
	flags.Float64Var(&triageMinEpss, "min-epss", 0, "Minimum EPSS score (0..1)")
	flags.Float64Var(&triageMinEpssPercentile, "min-epss-percentile", 0, "Minimum EPSS percentile (0..100)")
	flags.Float64Var(&triageMinCess, "min-cess", 0, "Minimum Coalition CESS score (0..10)")
	flags.Float64Var(&triageMinCvss, "min-cvss", 0, "Minimum best CVSS base score (0..10)")
	flags.StringVar(&vdbTriageSeverity, "severity", "", "CVSS severity: critical | high | medium | low")
	flags.StringVar(&triageInKev, "in-kev", "", "true to limit to KEV-listed CVEs, false to exclude them")
	flags.StringSliceVar(&triageKevSources, "kev-source", nil, "KEV source: CISA | vulnetix | enisa | vulncheck (repeat for OR)")
	flags.StringSliceVar(&triageCWEs, "cwe", nil, "Filter by CWE id (repeat for OR)")
	flags.StringVar(&triageVendor, "vendor", "", "ILIKE on affectedVendor")
	flags.StringVar(&triageProduct, "product", "", "ILIKE on affectedProduct")
	flags.StringVar(&triageSince, "since", "", "Only CVEs with datePublished >= RFC3339 (overrides --days)")
	flags.IntVarP(&triageDays, "days", "d", 0,
		"Look-back window in days (1..30). Default 0 = no implicit window. "+
			"Convenience for --since now-Nd; --since takes precedence when both are set.")
	flags.StringVar(&triageSort, "sort", "cvss",
		"Sort: cvss (default) | cess | epss (requires --min-epss >= 0.3) | published | kev-due")
	flags.IntVar(&triageLimit, "limit", 50, "Max items per page (1-200)")
	flags.IntVar(&triageOffset, "offset", 0, "Pagination offset")
	flags.StringVar(&vdbTriageFormat, "format", "json", "Output format: json | csv")
	flags.StringVarP(&triageOutput, "output", "o", "", "Write to this file")

	vdbCmd.AddCommand(vdbTriageCmd)
}
