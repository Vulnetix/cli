package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
)

var (
	vendorTrendsVendor string
	vendorTrendsYear   int
	trendsOutput       string
)

var vendorTrendsCmd = &cobra.Command{
	Use:   "vendor-trends",
	Short: "Vendor trend data — monthly/yearly CVE+GHSA breakdown",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()
		client.APIVersion = "/v2"
		q := url.Values{}
		if vendorTrendsVendor != "" {
			q.Set("vendor", vendorTrendsVendor)
		}
		if vendorTrendsYear > 0 {
			q.Set("year", fmt.Sprintf("%d", vendorTrendsYear))
		}
		path := "/vendor-trends"
		if encoded := q.Encode(); encoded != "" {
			path += "?" + encoded
		}
		body, err := client.DoRequest("GET", path, nil)
		if err != nil {
			return fmt.Errorf("vendor-trends: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("vendor-trends", vendorTrendsVendor)
		var pretty any
		_ = json.Unmarshal(body, &pretty)
		out, _ := json.MarshalIndent(pretty, "", "  ")
		return writeOutput(cmd, out, trendsOutput)
	},
}

var exploitTrendsCmd = &cobra.Command{
	Use:   "exploit-trends",
	Short: "Severity-tier rollup of exploit signal counts",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()
		client.APIVersion = "/v2"
		body, err := client.DoRequest("GET", "/exploit-trends", nil)
		if err != nil {
			return fmt.Errorf("exploit-trends: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("exploit-trends", "")
		var pretty any
		_ = json.Unmarshal(body, &pretty)
		out, _ := json.MarshalIndent(pretty, "", "  ")
		return writeOutput(cmd, out, trendsOutput)
	},
}

func init() {
	vendorTrendsCmd.Flags().StringVar(&vendorTrendsVendor, "vendor", "", "Filter to a specific vendor")
	vendorTrendsCmd.Flags().IntVar(&vendorTrendsYear, "year", 0, "Filter to a specific year (YYYY)")
	for _, c := range []*cobra.Command{vendorTrendsCmd, exploitTrendsCmd} {
		c.Flags().StringVarP(&trendsOutput, "output", "o", "", "Write JSON to this file")
	}
	vdbCmd.AddCommand(vendorTrendsCmd)
	vdbCmd.AddCommand(exploitTrendsCmd)
}
