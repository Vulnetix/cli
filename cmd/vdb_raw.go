package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	rawSource string
	rawOutput string
)

var rawCmd = &cobra.Command{
	Use:   "raw",
	Short: "Replay raw archived advisory bytes from object storage",
	Long: `Stream the original upstream advisory payload (JSON / XML) for a CVE.

Use cases (forensic / chain-of-custody):
  - Reproduce a vendor's published advisory exactly as it was at ingest time.
  - Audit how Vulnetix derived a particular CVE record.
  - Re-verify CVSS / SSVC scoring from raw inputs.

  vulnetix vdb raw sources                                # enumerate available sources
  vulnetix vdb raw get --source mitre-cve CVE-2021-44228  # per-CVE retrieval`,
}

var rawSourcesCmd = &cobra.Command{
	Use:   "sources",
	Short: "List sources whose raw archives are retrievable",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()
		client.APIVersion = "/v2"
		resp, err := client.V2RawSources()
		if err != nil {
			return fmt.Errorf("raw sources: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("raw-sources", "")
		body, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return err
		}
		return writeOutput(cmd, body, rawOutput)
	},
}

var rawGetCmd = &cobra.Command{
	Use:   "get <CVE-ID>",
	Short: "Fetch a CVE's raw upstream advisory bytes from S3",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if rawSource == "" {
			return fmt.Errorf("--source required (run `vulnetix vdb raw sources` to list)")
		}
		cveID := strings.ToUpper(strings.TrimSpace(args[0]))
		client := newVDBClient()
		client.APIVersion = "/v2"
		body, ct, sha, r2Path, err := client.V2RawArchive(rawSource, cveID)
		if err != nil {
			return fmt.Errorf("raw get: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("raw-get", rawSource+"/"+cveID)
		out := rawOutput
		if out == "" {
			out = fmt.Sprintf("%s-%s.bin", rawSource, cveID)
		}
		if err := os.WriteFile(out, body, 0o644); err != nil {
			return fmt.Errorf("write: %w", err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "wrote %d bytes to %s (content-type=%s, sha256=%s)\n", len(body), out, ct, sha)
		fmt.Fprintf(cmd.ErrOrStderr(), "r2-path: %s\n", r2Path)
		return nil
	},
}

func init() {
	rawGetCmd.Flags().StringVar(&rawSource, "source", "", "Source slug (mitre-cve, ghsa, osv, euvd, …)")
	for _, c := range []*cobra.Command{rawSourcesCmd, rawGetCmd} {
		c.Flags().StringVarP(&rawOutput, "output", "o", "", "Write to this file")
	}
	rawCmd.AddCommand(rawSourcesCmd)
	rawCmd.AddCommand(rawGetCmd)
	vdbCmd.AddCommand(rawCmd)
}
