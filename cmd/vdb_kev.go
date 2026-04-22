package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/pkg/vdb"
)

// VulnetixKevReason enum values — kept in sync with the VulnetixKevReason
// Postgres enum + the processor's reasons() output.
var validKevReasons = []string{
	"crowdsec_sighting",
	"misp_sighting",
	"shadowserver_sighting",
	"shadowserver_surge",
	"multi_source_sighting",
	"snort_rule",
	"nuclei_template",
	"metasploit_module",
	"known_ransomware",
	"critical_cvss",
}

// kev flags — shared across list + get subcommands
var (
	kevFormat     string
	kevReasons    []string
	kevAllReasons bool
	kevLimit      int
	kevOffset     int
	kevNoRefs     bool
	kevOutput     string
)

var kevCmd = &cobra.Command{
	Use:   "kev",
	Short: "Access the Vulnetix KEV (Known Exploited Vulnerabilities) catalogue",
	Long: `The Vulnetix KEV catalogue is an independent, evidence-driven list of
Known-Exploited-Vulnerabilities derived from multiple honeypot sources
(CrowdSec, MISP, Shadowserver) and weaponisation signals (Snort rules,
Nuclei templates, Metasploit modules) — for CVEs that are *not* already
in CISA KEV or VulnCheck KEV.

Each entry carries a ` + "`reasons`" + ` array (qualifying-path labels) plus the
standard KEV fields (vendor, product, required action, due date).`,
}

var kevListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the full Vulnetix KEV catalogue (JSON or CSV)",
	Long: `List every CVE in the Vulnetix KEV catalogue.

Filter by qualifying reason:

  vulnetix vdb kev list --reason known_ransomware
  vulnetix vdb kev list --reason snort_rule --reason metasploit_module     # OR
  vulnetix vdb kev list --reason snort_rule --reason critical_cvss --all   # AND

Export as CSV (downloads into the current directory if --output is omitted):

  vulnetix vdb kev list --format csv -o vulnetix-kev.csv

Use ` + "`vulnetix vdb kev reasons`" + ` to see the full list of qualifying reasons.`,
	RunE: runKevList,
}

var kevGetCmd = &cobra.Command{
	Use:   "get <CVE-ID>",
	Short: "Get a single Vulnetix KEV entry by CVE ID",
	Args:  cobra.ExactArgs(1),
	RunE:  runKevGet,
}

var kevReasonsCmd = &cobra.Command{
	Use:   "reasons",
	Short: "List valid Vulnetix KEV qualifying-reason enum values",
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, r := range validKevReasons {
			fmt.Fprintln(cmd.OutOrStdout(), r)
		}
		return nil
	},
}

var kevDownloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download the Vulnetix KEV catalogue as CSV (alias for `list --format csv`)",
	RunE: func(cmd *cobra.Command, args []string) error {
		kevFormat = "csv"
		if kevOutput == "" {
			kevOutput = "vulnetix-kev.csv"
		}
		return runKevList(cmd, args)
	},
}

func runKevList(cmd *cobra.Command, args []string) error {
	if err := validateReasons(kevReasons); err != nil {
		return err
	}
	format := strings.ToLower(kevFormat)
	if format != "csv" {
		format = "json"
	}
	params := vdb.VulnetixKevParams{
		Format:            format,
		Reasons:           kevReasons,
		Limit:             kevLimit,
		Offset:            kevOffset,
		IncludeReferences: format == "json" && !kevNoRefs,
	}
	if kevAllReasons {
		params.FilterMode = "all"
	}

	client := newVDBClient()
	body, err := client.VulnetixKevList(params)
	if err != nil {
		return fmt.Errorf("fetch Vulnetix KEV: %w", err)
	}
	printRateLimit(client)
	recordVDBQuery("kev-list", fmt.Sprintf("format=%s reasons=%s", format, strings.Join(kevReasons, ",")))

	return writeOutput(cmd, body, kevOutput)
}

func runKevGet(cmd *cobra.Command, args []string) error {
	cveID := strings.ToUpper(strings.TrimSpace(args[0]))
	client := newVDBClient()
	item, err := client.VulnetixKevGet(cveID)
	if err != nil {
		return err
	}
	printRateLimit(client)
	recordVDBQuery("kev-get", cveID)

	b, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return err
	}
	return writeOutput(cmd, b, kevOutput)
}

func validateReasons(rs []string) error {
	if len(rs) == 0 {
		return nil
	}
	valid := map[string]struct{}{}
	for _, r := range validKevReasons {
		valid[r] = struct{}{}
	}
	for _, r := range rs {
		if _, ok := valid[strings.ToLower(strings.TrimSpace(r))]; !ok {
			return fmt.Errorf("invalid --reason %q (run `vulnetix vdb kev reasons` to list valid values)", r)
		}
	}
	return nil
}

// writeOutput — print to stdout, or save to the given file path if non-empty.
func writeOutput(cmd *cobra.Command, body []byte, path string) error {
	if path == "" {
		_, err := cmd.OutOrStdout().Write(body)
		if err == nil && len(body) > 0 && body[len(body)-1] != '\n' {
			fmt.Fprintln(cmd.OutOrStdout())
		}
		return err
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "wrote %d bytes to %s\n", len(body), path)
	return nil
}

func init() {
	// Shared flags on list / download / get
	for _, c := range []*cobra.Command{kevListCmd, kevDownloadCmd} {
		c.Flags().StringVar(&kevFormat, "format", "json", "Output format: json or csv")
		c.Flags().StringSliceVar(&kevReasons, "reason", nil,
			"Filter by qualifying reason (repeatable). See `kev reasons` for valid values.")
		c.Flags().BoolVar(&kevAllReasons, "all", false,
			"Require every --reason to be present (AND). Default is any (OR).")
		c.Flags().IntVar(&kevLimit, "limit", 0, "Max items (JSON only; CSV streams the full set)")
		c.Flags().IntVar(&kevOffset, "offset", 0, "Pagination offset (JSON only)")
		c.Flags().BoolVar(&kevNoRefs, "no-references", false,
			"Omit the `references` bucket from each item (JSON only)")
		c.Flags().StringVarP(&kevOutput, "output", "o", "",
			"Write response body to this file instead of stdout")
	}
	kevGetCmd.Flags().StringVarP(&kevOutput, "output", "o", "",
		"Write the entry JSON to this file instead of stdout")

	kevCmd.AddCommand(kevListCmd)
	kevCmd.AddCommand(kevGetCmd)
	kevCmd.AddCommand(kevReasonsCmd)
	kevCmd.AddCommand(kevDownloadCmd)

	// Wire under the existing `vdb` command root (vulnetix vdb kev …)
	vdbCmd.AddCommand(kevCmd)
}
