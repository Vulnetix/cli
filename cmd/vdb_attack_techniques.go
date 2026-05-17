package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

var (
	atkSearchTechniques []string
	atkSearchTactics    []string
	atkSearchCveIDs     []string
	atkSearchSources    []string
	atkSearchCapec      string
	atkSearchDomain     string
	atkSearchSubtech    string
	atkSearchDerivedBy  string
	atkSearchQ          string
	atkSearchSince      string
	atkSearchUntil      string
	atkSearchLimit      int
	atkSearchOffset     int
	atkSearchOutput     string
)

var attackTechniquesCmd = &cobra.Command{
	Use:   "attack-techniques",
	Short: "Look up MITRE ATT&CK technique mappings for CVEs",
	Long: `MITRE ATT&CK technique mappings — how an attacker exploits a
vulnerability — including each technique's mitigations, detections, and
D3FEND counter-techniques.

Per-CVE:
  vulnetix vdb attack-techniques get CVE-2021-44228

Cross-CVE search by technique:
  vulnetix vdb attack-techniques list --technique T1190
  vulnetix vdb attack-techniques list --tactic execution --tactic lateral-movement
  vulnetix vdb attack-techniques list --capec CAPEC-242 --domain Enterprise
  vulnetix vdb attack-techniques list --derived-by vulnetix --q "remote code"`,
}

var attackTechniquesGetCmd = &cobra.Command{
	Use:   "get <CVE-ID>",
	Short: "Get the ATT&CK technique mapping for a single CVE",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cveID := strings.ToUpper(strings.TrimSpace(args[0]))
		client := newVDBClient()
		client.APIVersion = "/v2"
		resp, err := client.V2AttackTechniques(cveID)
		if err != nil {
			return fmt.Errorf("attack-techniques get: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("attack-techniques-get", cveID)
		body, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return err
		}
		return writeOutput(cmd, body, atkSearchOutput)
	},
}

var attackTechniquesListCmd = &cobra.Command{
	Use:   "list",
	Short: "Search ATT&CK technique mappings across CVEs",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()
		client.APIVersion = "/v2"
		resp, err := client.V2AttackTechniquesSearch(vdb.AttackTechniquesSearchParams{
			TechniqueIDs: atkSearchTechniques,
			Tactics:      atkSearchTactics,
			CveIDs:       upperAll(atkSearchCveIDs),
			Sources:      atkSearchSources,
			CapecID:      atkSearchCapec,
			Domain:       atkSearchDomain,
			Subtechnique: atkSearchSubtech,
			DerivedBy:    atkSearchDerivedBy,
			Q:            atkSearchQ,
			Since:        atkSearchSince,
			Until:        atkSearchUntil,
			Limit:        atkSearchLimit,
			Offset:       atkSearchOffset,
		})
		if err != nil {
			return fmt.Errorf("attack-techniques list: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("attack-techniques-list", summariseAttackQuery())
		body, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return err
		}
		return writeOutput(cmd, body, atkSearchOutput)
	},
}

func summariseAttackQuery() string {
	parts := []string{}
	if len(atkSearchTechniques) > 0 {
		parts = append(parts, "tech="+strings.Join(atkSearchTechniques, ","))
	}
	if len(atkSearchTactics) > 0 {
		parts = append(parts, "tactic="+strings.Join(atkSearchTactics, ","))
	}
	if atkSearchCapec != "" {
		parts = append(parts, "capec="+atkSearchCapec)
	}
	if atkSearchQ != "" {
		parts = append(parts, "q="+atkSearchQ)
	}
	return strings.Join(parts, " ")
}

func upperAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, strings.ToUpper(s))
		}
	}
	return out
}

func init() {
	// Filters — list only
	attackTechniquesListCmd.Flags().StringSliceVar(&atkSearchTechniques, "technique", nil,
		"MITRE ATT&CK technique id (e.g. T1190 or T1547.004; repeat for OR)")
	attackTechniquesListCmd.Flags().StringSliceVar(&atkSearchTactics, "tactic", nil,
		"ATT&CK tactic kebab-case (e.g. execution, lateral-movement; repeat for AND)")
	attackTechniquesListCmd.Flags().StringSliceVar(&atkSearchCveIDs, "cve-id", nil,
		"Limit to one or more CVE IDs (repeat)")
	attackTechniquesListCmd.Flags().StringSliceVar(&atkSearchSources, "source", nil,
		"CVEMetadata.source filter (e.g. nist-nvd, mitre-cve; repeat)")
	attackTechniquesListCmd.Flags().StringVar(&atkSearchCapec, "capec", "",
		"CAPEC id (e.g. CAPEC-242 or just 242)")
	attackTechniquesListCmd.Flags().StringVar(&atkSearchDomain, "domain", "",
		"ATT&CK domain: Enterprise | Mobile | ICS")
	attackTechniquesListCmd.Flags().StringVar(&atkSearchSubtech, "subtechnique", "",
		"true to require sub-techniques only, false to exclude them")
	attackTechniquesListCmd.Flags().StringVar(&atkSearchDerivedBy, "derived-by", "",
		"Provenance filter (e.g. vulnetix for AI-derived rows only)")
	attackTechniquesListCmd.Flags().StringVar(&atkSearchQ, "q", "",
		"Free-text search on technique name")
	attackTechniquesListCmd.Flags().StringVar(&atkSearchSince, "since", "",
		"Only mappings created at or after this RFC3339 timestamp")
	attackTechniquesListCmd.Flags().StringVar(&atkSearchUntil, "until", "",
		"Only mappings created at or before this RFC3339 timestamp")
	attackTechniquesListCmd.Flags().IntVar(&atkSearchLimit, "limit", 50, "Max items per page (1-200)")
	attackTechniquesListCmd.Flags().IntVar(&atkSearchOffset, "offset", 0, "Pagination offset")

	// Output flag — both subcommands
	for _, c := range []*cobra.Command{attackTechniquesGetCmd, attackTechniquesListCmd} {
		c.Flags().StringVarP(&atkSearchOutput, "output", "o", "",
			"Write JSON to this file instead of stdout")
	}

	attackTechniquesCmd.AddCommand(attackTechniquesGetCmd)
	attackTechniquesCmd.AddCommand(attackTechniquesListCmd)
	vdbCmd.AddCommand(attackTechniquesCmd)
}
