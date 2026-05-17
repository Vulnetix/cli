package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

var (
	snortSearchCveIDs           []string
	snortSearchSources          []string
	snortSearchTechniques       []string
	snortSearchTactics          []string
	snortSearchAffectedProducts []string
	snortSearchTags             []string
	snortSearchClasstype        string
	snortSearchSeverity         string
	snortSearchProtocol         string
	snortSearchAction           string
	snortSearchDstPort          string
	snortSearchSrcPort          string
	snortSearchDisabled         string
	snortSearchQ                string
	snortSearchSince            string
	snortSearchUntil            string
	snortSearchSort             string
	snortSearchLimit            int
	snortSearchOffset           int
	snortSearchOutput           string
	snortSearchFormat           string // json | rules
)

var snortRulesCmd = &cobra.Command{
	Use:   "snort-rules",
	Short: "Look up Snort detection rules with rich filters",
	Long: `Snort/Suricata IDS signatures attached to CVEs.

Per-CVE:
  vulnetix vdb snort-rules get CVE-2021-44228

Search across the catalogue:
  vulnetix vdb snort-rules list --technique T1190 --severity high
  vulnetix vdb snort-rules list --classtype web-application-attack --protocol http
  vulnetix vdb snort-rules list --dst-port '$HTTP_PORTS' --match-content "log4j"
  vulnetix vdb snort-rules list --source emergingthreats --tag exploit
  vulnetix vdb snort-rules list --since 2026-01-01T00:00:00Z --sort severity

Output as raw .rules-file syntax instead of JSON:
  vulnetix vdb snort-rules list --technique T1059 --format rules`,
}

var snortRulesGetCmd = &cobra.Command{
	Use:   "get <CVE-ID>",
	Short: "Get all Snort rules linked to a single CVE",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cveID := strings.ToUpper(strings.TrimSpace(args[0]))
		client := newVDBClient()
		client.APIVersion = "/v2"
		resp, err := client.V2SnortRules(cveID)
		if err != nil {
			return fmt.Errorf("snort-rules get: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("snort-rules-get", cveID)
		return emitRulesResponse(cmd, resp, snortSearchFormat, snortSearchOutput)
	},
}

var snortRulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "Search Snort rules across all CVEs with expressive filters",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()
		client.APIVersion = "/v2"
		resp, err := client.V2SnortRulesSearch(vdb.SnortSearchParams{
			CveIDs:           upperAll(snortSearchCveIDs),
			Sources:          snortSearchSources,
			Techniques:       snortSearchTechniques,
			Tactics:          snortSearchTactics,
			Classtype:        snortSearchClasstype,
			Severity:         snortSearchSeverity,
			Protocol:         snortSearchProtocol,
			Action:           snortSearchAction,
			DstPort:          snortSearchDstPort,
			SrcPort:          snortSearchSrcPort,
			Disabled:         snortSearchDisabled,
			Q:                snortSearchQ,
			AffectedProducts: snortSearchAffectedProducts,
			Tags:             snortSearchTags,
			Since:            snortSearchSince,
			Until:            snortSearchUntil,
			Sort:             snortSearchSort,
			Limit:            snortSearchLimit,
			Offset:           snortSearchOffset,
		})
		if err != nil {
			return fmt.Errorf("snort-rules list: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("snort-rules-list", summariseSnortQuery())
		return emitRulesResponse(cmd, resp, snortSearchFormat, snortSearchOutput)
	},
}

// emitRulesResponse writes a rules response either as JSON or as raw .rules
// concatenated rawText (one per line), depending on format.
func emitRulesResponse(cmd *cobra.Command, resp map[string]interface{}, format, output string) error {
	if strings.ToLower(format) == "rules" {
		var b strings.Builder
		if rules, ok := resp["rules"].([]interface{}); ok {
			for _, r := range rules {
				if m, ok := r.(map[string]interface{}); ok {
					if raw, ok := m["rawText"].(string); ok && raw != "" {
						b.WriteString(strings.TrimRight(raw, "\n"))
						b.WriteString("\n")
					}
				}
			}
		}
		return writeOutput(cmd, []byte(b.String()), output)
	}
	body, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return err
	}
	return writeOutput(cmd, body, output)
}

func summariseSnortQuery() string {
	parts := []string{}
	if len(snortSearchTechniques) > 0 {
		parts = append(parts, "tech="+strings.Join(snortSearchTechniques, ","))
	}
	if snortSearchClasstype != "" {
		parts = append(parts, "class="+snortSearchClasstype)
	}
	if snortSearchSeverity != "" {
		parts = append(parts, "sev="+snortSearchSeverity)
	}
	if snortSearchQ != "" {
		parts = append(parts, "q="+snortSearchQ)
	}
	return strings.Join(parts, " ")
}

func init() {
	listFlags := snortRulesListCmd.Flags()
	listFlags.StringSliceVar(&snortSearchCveIDs, "cve-id", nil,
		"Limit to one or more CVE IDs (repeat)")
	listFlags.StringSliceVar(&snortSearchSources, "source", nil,
		"Rule source (e.g. snort-registered, emergingthreats, vulnetix; repeat for OR)")
	listFlags.StringSliceVar(&snortSearchTechniques, "technique", nil,
		"MITRE ATT&CK technique id in the rule's mitreTechIds (repeat for AND)")
	listFlags.StringSliceVar(&snortSearchTactics, "tactic", nil,
		"MITRE ATT&CK tactic id in mitreTacticIds (repeat for AND)")
	listFlags.StringSliceVar(&snortSearchAffectedProducts, "affected-product", nil,
		"affectedProducts contains (repeat for AND)")
	listFlags.StringSliceVar(&snortSearchTags, "tag", nil,
		"tags contains (repeat for AND)")
	listFlags.StringVar(&snortSearchClasstype, "classtype", "",
		"Snort classtype (e.g. attempted-admin, web-application-attack)")
	listFlags.StringVar(&snortSearchSeverity, "severity", "",
		"signatureSeverity: informational | low | medium | high | critical")
	listFlags.StringVar(&snortSearchProtocol, "protocol", "",
		"Protocol: tcp | udp | http | tls | ip")
	listFlags.StringVar(&snortSearchAction, "action", "",
		"Action: alert | drop | reject | log")
	listFlags.StringVar(&snortSearchDstPort, "dst-port", "",
		`Destination port (e.g. 443, "$HTTP_PORTS", any)`)
	listFlags.StringVar(&snortSearchSrcPort, "src-port", "",
		"Source port")
	listFlags.StringVar(&snortSearchDisabled, "disabled", "",
		"true to limit to disabled rules, false to exclude them")
	listFlags.StringVar(&snortSearchQ, "match-content", "",
		"Free-text ILIKE on msg + rawText (whitespace-separated tokens AND)")
	listFlags.StringVar(&snortSearchSince, "since", "",
		"Only rules with datePublished >= this RFC3339 timestamp")
	listFlags.StringVar(&snortSearchUntil, "until", "",
		"Only rules with datePublished <= this RFC3339 timestamp")
	listFlags.StringVar(&snortSearchSort, "sort", "recent",
		"Sort order: recent | severity | id")
	listFlags.IntVar(&snortSearchLimit, "limit", 50, "Max items per page (1-200)")
	listFlags.IntVar(&snortSearchOffset, "offset", 0, "Pagination offset")

	for _, c := range []*cobra.Command{snortRulesGetCmd, snortRulesListCmd} {
		c.Flags().StringVar(&snortSearchFormat, "format", "json",
			"Output format: json | rules (raw .rules-file syntax)")
		c.Flags().StringVarP(&snortSearchOutput, "output", "o", "",
			"Write response to this file instead of stdout")
	}

	snortRulesCmd.AddCommand(snortRulesGetCmd)
	snortRulesCmd.AddCommand(snortRulesListCmd)
	vdbCmd.AddCommand(snortRulesCmd)
}
