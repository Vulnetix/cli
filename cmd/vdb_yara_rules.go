package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

var (
	yaraSearchCveIDs   []string
	yaraSearchSources  []string
	yaraSearchTags     []string
	yaraSearchImports  []string
	yaraSearchRuleName string
	yaraSearchAuthor   string
	yaraSearchQ        string
	yaraSearchString   string
	yaraSearchMeta     string
	yaraSearchSince    string
	yaraSearchUntil    string
	yaraSearchSort     string
	yaraSearchLimit    int
	yaraSearchOffset   int
	yaraSearchOutput   string
	yaraSearchFormat   string // json | rules
)

var yaraRulesCmd = &cobra.Command{
	Use:   "yara-rules",
	Short: "Look up YARA static-analysis rules with rich filters",
	Long: `YARA rules attached to CVEs.

Per-CVE:
  vulnetix vdb yara-rules get CVE-2021-44228

Search across the catalogue:
  vulnetix vdb yara-rules list --rule-name 'apt%' --tag exploit
  vulnetix vdb yara-rules list --author "Florian Roth" --imports pe
  vulnetix vdb yara-rules list --match-string "log4j" --match-meta "severity=high"
  vulnetix vdb yara-rules list --source vulnetix --since 2026-01-01T00:00:00Z

Output as raw .yar concatenation:
  vulnetix vdb yara-rules list --tag ransomware --format rules > pack.yar`,
}

var yaraRulesGetCmd = &cobra.Command{
	Use:   "get <CVE-ID>",
	Short: "Get all YARA rules linked to a single CVE",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cveID := strings.ToUpper(strings.TrimSpace(args[0]))
		client := newVDBClient()
		client.APIVersion = "/v2"
		resp, err := client.V2YaraRules(cveID)
		if err != nil {
			return fmt.Errorf("yara-rules get: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("yara-rules-get", cveID)
		return emitYaraResponse(cmd, resp, yaraSearchFormat, yaraSearchOutput)
	},
}

var yaraRulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "Search YARA rules across all CVEs with expressive filters",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()
		client.APIVersion = "/v2"
		resp, err := client.V2YaraRulesSearch(vdb.YaraSearchParams{
			CveIDs:      upperAll(yaraSearchCveIDs),
			Sources:     yaraSearchSources,
			Tags:        yaraSearchTags,
			Imports:     yaraSearchImports,
			RuleName:    yaraSearchRuleName,
			Author:      yaraSearchAuthor,
			Q:           yaraSearchQ,
			MatchString: yaraSearchString,
			MatchMeta:   yaraSearchMeta,
			Since:       yaraSearchSince,
			Until:       yaraSearchUntil,
			Sort:        yaraSearchSort,
			Limit:       yaraSearchLimit,
			Offset:      yaraSearchOffset,
		})
		if err != nil {
			return fmt.Errorf("yara-rules list: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("yara-rules-list", summariseYaraQuery())
		return emitYaraResponse(cmd, resp, yaraSearchFormat, yaraSearchOutput)
	},
}

func emitYaraResponse(cmd *cobra.Command, resp map[string]interface{}, format, output string) error {
	if strings.ToLower(format) == "rules" {
		var b strings.Builder
		if rules, ok := resp["rules"].([]interface{}); ok {
			for _, r := range rules {
				if m, ok := r.(map[string]interface{}); ok {
					if raw, ok := m["rawText"].(string); ok && raw != "" {
						b.WriteString(strings.TrimRight(raw, "\n"))
						b.WriteString("\n\n")
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

func summariseYaraQuery() string {
	parts := []string{}
	if yaraSearchRuleName != "" {
		parts = append(parts, "name="+yaraSearchRuleName)
	}
	if len(yaraSearchTags) > 0 {
		parts = append(parts, "tag="+strings.Join(yaraSearchTags, ","))
	}
	if yaraSearchQ != "" {
		parts = append(parts, "q="+yaraSearchQ)
	}
	return strings.Join(parts, " ")
}

func init() {
	listFlags := yaraRulesListCmd.Flags()
	listFlags.StringSliceVar(&yaraSearchCveIDs, "cve-id", nil,
		"Limit to one or more CVE IDs (repeat)")
	listFlags.StringSliceVar(&yaraSearchSources, "source", nil,
		"Rule source (e.g. yara-forge, yarahub, vulnetix; repeat for OR)")
	listFlags.StringSliceVar(&yaraSearchTags, "tag", nil,
		"tags contains (repeat for AND)")
	listFlags.StringSliceVar(&yaraSearchImports, "imports", nil,
		"YARA module imports (e.g. pe, math, hash; repeat for AND)")
	listFlags.StringVar(&yaraSearchRuleName, "rule-name", "",
		"Filter by rule name (substring or SQL ILIKE pattern with %)")
	listFlags.StringVar(&yaraSearchAuthor, "author", "",
		"Filter by author (ILIKE substring)")
	listFlags.StringVar(&yaraSearchQ, "match-content", "",
		"Free-text ILIKE on rawText + strings + meta (whitespace-separated tokens AND)")
	listFlags.StringVar(&yaraSearchString, "match-string", "",
		"ILIKE inside the strings field only")
	listFlags.StringVar(&yaraSearchMeta, "match-meta", "",
		`ILIKE inside the meta field (e.g. "severity=high")`)
	listFlags.StringVar(&yaraSearchSince, "since", "",
		"Only rules with datePublished >= this RFC3339 timestamp")
	listFlags.StringVar(&yaraSearchUntil, "until", "",
		"Only rules with datePublished <= this RFC3339 timestamp")
	listFlags.StringVar(&yaraSearchSort, "sort", "recent",
		"Sort order: recent | name")
	listFlags.IntVar(&yaraSearchLimit, "limit", 50, "Max items per page (1-200)")
	listFlags.IntVar(&yaraSearchOffset, "offset", 0, "Pagination offset")

	for _, c := range []*cobra.Command{yaraRulesGetCmd, yaraRulesListCmd} {
		c.Flags().StringVar(&yaraSearchFormat, "format", "json",
			"Output format: json | rules (raw .yar concatenation)")
		c.Flags().StringVarP(&yaraSearchOutput, "output", "o", "",
			"Write response to this file instead of stdout")
	}

	yaraRulesCmd.AddCommand(yaraRulesGetCmd)
	yaraRulesCmd.AddCommand(yaraRulesListCmd)
	vdbCmd.AddCommand(yaraRulesCmd)
}
