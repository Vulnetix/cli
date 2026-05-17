package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v2/pkg/vdb"
)

var (
	iocsListCveIDs     []string
	iocsListCountries  []string
	iocsListASNs       []int
	iocsListBehavior   string
	iocsListReputation string
	iocsListSince      string
	iocsListLimit      int
	iocsListOffset     int
	iocsListFormat     string
	iocsOutput         string
)

var iocsCmd = &cobra.Command{
	Use:   "iocs",
	Short: "IOC pivots from CrowdSec sightings + Shadowserver counts",
	Long: `IOC (indicators of compromise) pivots — IPs, ASNs, geolocation, behaviors,
and ATT&CK techniques observed by the CrowdSec community against a CVE.

Per-CVE:
  vulnetix vdb iocs CVE-2021-44228

Cross-CVE search:
  vulnetix vdb iocs list --cve-id CVE-2021-44228 --country US --behavior http-scanning
  vulnetix vdb iocs list --asn 13335 --since 2026-04-01T00:00:00Z

STIX 2.1 bundle for SOAR/SIEM ingest (Splunk, Sentinel, Cortex, Tines):
  vulnetix vdb iocs list --cve-id CVE-2021-44228 --format stix > iocs.stix.json`,
}

var iocsGetCmd = &cobra.Command{
	Use:   "get <CVE-ID>",
	Short: "IOC sightings + Shadowserver summary for a single CVE",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cveID := strings.ToUpper(strings.TrimSpace(args[0]))
		client := newVDBClient()
		client.APIVersion = "/v2"
		resp, err := client.V2VulnIOCs(cveID)
		if err != nil {
			return fmt.Errorf("iocs get: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("iocs-get", cveID)
		body, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return err
		}
		return writeOutput(cmd, body, iocsOutput)
	},
}

var iocsListCmd = &cobra.Command{
	Use:   "list",
	Short: "Search IOC sightings across CVEs",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()
		client.APIVersion = "/v2"
		body, _, err := client.V2IOCsSearch(vdb.IOCSearchParams{
			CveIDs:     upperAll(iocsListCveIDs),
			Countries:  iocsListCountries,
			ASNs:       iocsListASNs,
			Behavior:   iocsListBehavior,
			Reputation: iocsListReputation,
			Since:      iocsListSince,
			Format:     iocsListFormat,
			Limit:      iocsListLimit,
			Offset:     iocsListOffset,
		})
		if err != nil {
			return fmt.Errorf("iocs list: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("iocs-list", iocsListBehavior)

		switch strings.ToLower(strings.TrimSpace(iocsListFormat)) {
		case "csv":
			return emitIOCsCSV(cmd, body)
		default:
			return writeOutput(cmd, body, iocsOutput)
		}
	},
}

func emitIOCsCSV(cmd *cobra.Command, body []byte) error {
	var resp struct {
		Sightings []map[string]any `json:"sightings"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("decode for csv: %w", err)
	}
	w := csv.NewWriter(cmd.OutOrStdout())
	defer w.Flush()
	_ = w.Write([]string{"cveId", "ip", "asNum", "asName", "country", "city", "reputation", "confidence", "firstSeen", "lastSeen", "behaviors", "mitreTechniques"})
	for _, s := range resp.Sightings {
		row := []string{
			str(s["cveId"]), str(s["ip"]), str(s["asNum"]), str(s["asName"]),
			str(s["country"]), str(s["city"]), str(s["reputation"]), str(s["confidence"]),
			str(s["firstSeen"]), str(s["lastSeen"]),
			joinSlice(s["behaviors"]), joinSlice(s["mitreTechniques"]),
		}
		_ = w.Write(row)
	}
	return nil
}

func str(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%g", x)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func joinSlice(v any) string {
	if v == nil {
		return ""
	}
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		out = append(out, str(x))
	}
	return strings.Join(out, "|")
}

func init() {
	listFlags := iocsListCmd.Flags()
	listFlags.StringSliceVar(&iocsListCveIDs, "cve-id", nil, "Restrict to one or more CVE IDs (repeat)")
	listFlags.StringSliceVar(&iocsListCountries, "country", nil, "ISO-2 country code (repeatable; AND)")
	listFlags.IntSliceVar(&iocsListASNs, "asn", nil, "AS number (repeatable; AND)")
	listFlags.StringVar(&iocsListBehavior, "behavior", "", "Substring of CrowdSec behaviorsCsv")
	listFlags.StringVar(&iocsListReputation, "reputation", "", "Exact reputation (e.g. malicious)")
	listFlags.StringVar(&iocsListSince, "since", "", "Only sightings with lastSeen >= RFC3339")
	listFlags.IntVar(&iocsListLimit, "limit", 100, "Max items per page (1-500)")
	listFlags.IntVar(&iocsListOffset, "offset", 0, "Pagination offset")
	listFlags.StringVar(&iocsListFormat, "format", "json", "Output format: json | csv | stix")

	for _, c := range []*cobra.Command{iocsGetCmd, iocsListCmd} {
		c.Flags().StringVarP(&iocsOutput, "output", "o", "", "Write to this file instead of stdout")
	}

	iocsCmd.AddCommand(iocsGetCmd)
	iocsCmd.AddCommand(iocsListCmd)
	vdbCmd.AddCommand(iocsCmd)
}
