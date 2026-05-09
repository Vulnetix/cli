package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var msrcOutput string

var msrcCmd = &cobra.Command{
	Use:   "msrc",
	Short: "Microsoft Security Response Center patch-tuesday rollups",
	Long: `Microsoft Security Response Center monthly Patch Tuesday rollups.

  vulnetix vdb msrc patch-tuesdays
  vulnetix vdb msrc patch-tuesday 2026-04`,
}

var msrcListCmd = &cobra.Command{
	Use:   "patch-tuesdays",
	Short: "List Microsoft Patch Tuesday months on file",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()
		client.APIVersion = "/v2"
		body, err := client.DoRequest("GET", "/msrc/patch-tuesdays", nil)
		if err != nil {
			return fmt.Errorf("msrc patch-tuesdays: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("msrc-patch-tuesdays", "")
		var pretty any
		_ = json.Unmarshal(body, &pretty)
		out, _ := json.MarshalIndent(pretty, "", "  ")
		return writeOutput(cmd, out, msrcOutput)
	},
}

var msrcGetCmd = &cobra.Command{
	Use:   "patch-tuesday <YYYY-MM>",
	Short: "Get a specific Patch Tuesday rollup by ISO month",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		date := strings.TrimSpace(args[0])
		client := newVDBClient()
		client.APIVersion = "/v2"
		body, err := client.DoRequest("GET", fmt.Sprintf("/msrc/patch-tuesday/%s", date), nil)
		if err != nil {
			return fmt.Errorf("msrc patch-tuesday: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("msrc-patch-tuesday", date)
		var pretty any
		_ = json.Unmarshal(body, &pretty)
		out, _ := json.MarshalIndent(pretty, "", "  ")
		return writeOutput(cmd, out, msrcOutput)
	},
}

func init() {
	for _, c := range []*cobra.Command{msrcListCmd, msrcGetCmd} {
		c.Flags().StringVarP(&msrcOutput, "output", "o", "", "Write JSON to this file")
	}
	msrcCmd.AddCommand(msrcListCmd)
	msrcCmd.AddCommand(msrcGetCmd)
	vdbCmd.AddCommand(msrcCmd)
}
