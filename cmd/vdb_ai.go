package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
)

var (
	aiCveID  string
	aiSince  string
	aiLimit  int
	aiOutput string
)

func aiSimpleGet(cmd *cobra.Command, label, path string) error {
	client := newVDBClient()
	client.APIVersion = "/v2"
	q := url.Values{}
	if aiCveID != "" {
		q.Set("cveId", aiCveID)
	}
	if aiSince != "" {
		q.Set("since", aiSince)
	}
	if aiLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", aiLimit))
	}
	full := path
	if encoded := q.Encode(); encoded != "" {
		full += "?" + encoded
	}
	body, err := client.DoRequest("GET", full, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	printRateLimit(client)
	recordVDBQuery(label, aiCveID)
	var pretty any
	_ = json.Unmarshal(body, &pretty)
	out, _ := json.MarshalIndent(pretty, "", "  ")
	return writeOutput(cmd, out, aiOutput)
}

var aiDiscoveriesCmd = &cobra.Command{
	Use:   "ai-discoveries",
	Short: "AI-discovered vulnerabilities (researcher leaderboard + per-CVE)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return aiSimpleGet(cmd, "ai-discoveries", "/ai-discoveries")
	},
}

var aiAssistedCmd = &cobra.Command{
	Use:   "ai-assisted-exploits",
	Short: "Researcher AI-assisted exploit demonstrations",
	RunE: func(cmd *cobra.Command, args []string) error {
		return aiSimpleGet(cmd, "ai-assisted-exploits", "/ai-assisted-exploits")
	},
}

var aiInWildCmd = &cobra.Command{
	Use:   "ai-in-wild",
	Short: "AI-discovered in-the-wild exploitation observations",
	RunE: func(cmd *cobra.Command, args []string) error {
		return aiSimpleGet(cmd, "ai-in-wild-exploitations", "/ai-in-wild-exploitations")
	},
}

var aiMalwareCmd = &cobra.Command{
	Use:   "ai-malware",
	Short: "AI-authored / AI-runtime malware family intelligence",
	RunE: func(cmd *cobra.Command, args []string) error {
		return aiSimpleGet(cmd, "ai-generated-malware", "/ai-generated-malware")
	},
}

func init() {
	for _, c := range []*cobra.Command{aiDiscoveriesCmd, aiAssistedCmd, aiInWildCmd, aiMalwareCmd} {
		c.Flags().StringVar(&aiCveID, "cve", "", "Filter to a specific CVE ID")
		c.Flags().StringVar(&aiSince, "since", "", "Filter to events at or after RFC3339")
		c.Flags().IntVar(&aiLimit, "limit", 50, "Max items per page")
		c.Flags().StringVarP(&aiOutput, "output", "o", "", "Write JSON to this file")
		vdbCmd.AddCommand(c)
	}
}
