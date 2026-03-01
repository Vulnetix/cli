package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/internal/auth"
	"github.com/vulnetix/cli/internal/vdb"
)

var (
	vdbOrgID     string
	vdbSecretKey string
	vdbBaseURL   string
	vdbOutput    string
	vdbCreds     *auth.Credentials
)

// vdbCmd represents the vdb command
var vdbCmd = &cobra.Command{
	Use:   "vdb",
	Short: "Interact with the Vulnetix Vulnerability Database (VDB) API",
	Long: `Access and query the Vulnetix Vulnerability Database (VDB) API.

The VDB API provides comprehensive vulnerability intelligence from multiple authoritative sources
including MITRE CVE, NIST NVD, CISA KEV, and many others.

Authentication:
  Set credentials via environment variables:
    export VVD_ORG="your-organization-uuid"
    export VVD_SECRET="your-secret-key"

  Or create a config file at ~/.vulnetix/vdb.json:
    {
      "org_id": "your-organization-uuid",
      "secret_key": "your-secret-key"
    }

Examples:
  # Get information about a vulnerability (CVE, GHSA, PYSEC, ZDI, and 70+ more formats)
  vulnetix vdb vuln CVE-2021-44228
  vulnetix vdb vuln GHSA-jfh8-3a1q-hjz9

  # List available ecosystems
  vulnetix vdb ecosystems

  # Get versions for a product
  vulnetix vdb product express

  # Get vulnerabilities for a package
  vulnetix vdb vulns express`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Load credentials if not provided via flags
		if vdbOrgID == "" || vdbSecretKey == "" {
			creds, err := vdb.LoadFullCredentials()
			if err != nil {
				return err
			}
			vdbCreds = creds
			if vdbOrgID == "" {
				vdbOrgID = creds.OrgID
			}
			if vdbSecretKey == "" {
				vdbSecretKey = creds.Secret
			}
		} else {
			// Flags provided — use SigV4 as default
			vdbCreds = &auth.Credentials{
				OrgID:  vdbOrgID,
				Secret: vdbSecretKey,
				Method: auth.SigV4,
			}
		}
		return nil
	},
}

// vulnCmd retrieves information about a specific vulnerability
var vulnCmd = &cobra.Command{
	Use:   "vuln <vuln-id>",
	Short: "Get information about a specific vulnerability",
	Long: `Retrieve full vulnerability data for any supported vulnerability identifier, including
descriptions, CVSS metrics, CWEs, affected products, EPSS scores, and KEV status from all
available sources.

Accepts 78+ identifier formats. Common examples:
  CVE-2021-44228         (MITRE / NVD)
  GHSA-jfh8-3a1q-hjz9   (GitHub Security Advisories)
  PYSEC-2024-123         (PyPI)
  RUSTSEC-2024-1234      (RustSec)
  EUVD-2025-14498        (EU Vulnerability Database)
  RHSA-2025:1730         (Red Hat)
  DSA-4741-1             (Debian)
  USN-7040-1             (Ubuntu)
  ZDI-23-1714            (Zero Day Initiative)
  SNYK-JAVA-ORGCLOJURE-5740378 (Snyk)

Examples:
  vulnetix vdb vuln CVE-2021-44228
  vulnetix vdb vuln GHSA-jfh8-3a1q-hjz9
  vulnetix vdb vuln CVE-2021-44228 --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cveID := args[0]

		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintf(os.Stderr, "🔍 Fetching information for %s...\n", cveID)
		} else {
			fmt.Printf("🔍 Fetching information for %s...\n", cveID)
		}

		cveInfo, err := client.GetCVE(cveID)
		if err != nil {
			return fmt.Errorf("failed to get CVE: %w", err)
		}
		printRateLimit(client)

		return printOutput(cveInfo.Data, vdbOutput)
	},
}

// exploitsCmd retrieves exploit intelligence for a specific vulnerability
var exploitsCmd = &cobra.Command{
	Use:   "exploits <vuln-id>",
	Short: "Get exploit intelligence for a specific vulnerability",
	Long: `Retrieve exploit intelligence for a vulnerability, aggregating data from multiple exploit
databases including ExploitDB, Metasploit modules, Nuclei templates, VulnCheck, CrowdSec, and
GitHub proof-of-concept repositories.

Accepts any supported vulnerability identifier (CVE, GHSA, PYSEC, ZDI, SNYK, and 70+ more).

Examples:
  vulnetix vdb exploits CVE-2021-44228
  vulnetix vdb exploits GHSA-jfh8-3a1q-hjz9
  vulnetix vdb exploits CVE-2021-44228 --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		identifier := args[0]

		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintf(os.Stderr, "💥 Fetching exploit intelligence for %s...\n", identifier)
		} else {
			fmt.Printf("💥 Fetching exploit intelligence for %s...\n", identifier)
		}

		result, err := client.GetExploits(identifier)
		if err != nil {
			return fmt.Errorf("failed to get exploits: %w", err)
		}
		printRateLimit(client)

		return printOutput(result, vdbOutput)
	},
}

// fixesCmd retrieves fix data for a specific vulnerability
var fixesCmd = &cobra.Command{
	Use:   "fixes <vuln-id>",
	Short: "Get fix data for a specific vulnerability",
	Long: `Retrieve comprehensive fix data for a vulnerability including patches, advisories,
workarounds, KEV required actions, and AI-generated analysis.

Accepts any supported vulnerability identifier (CVE, GHSA, PYSEC, ZDI, SNYK, and 70+ more).

Examples:
  vulnetix vdb fixes CVE-2021-44228
  vulnetix vdb fixes GHSA-jfh8-3a1q-hjz9
  vulnetix vdb fixes CVE-2021-44228 --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		identifier := args[0]

		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintf(os.Stderr, "🔧 Fetching fix data for %s...\n", identifier)
		} else {
			fmt.Printf("🔧 Fetching fix data for %s...\n", identifier)
		}

		result, err := client.GetCVEFixes(identifier)
		if err != nil {
			return fmt.Errorf("failed to get fixes: %w", err)
		}
		printRateLimit(client)

		return printOutput(result, vdbOutput)
	},
}

// versionsCmd retrieves all known versions for a package across ecosystems
var versionsCmd = &cobra.Command{
	Use:   "versions <package-name>",
	Short: "Get all versions of a package across ecosystems",
	Long: `List all known versions for a package across ecosystems.

Examples:
  vulnetix vdb versions express
  vulnetix vdb versions express --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		packageName := args[0]

		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintf(os.Stderr, "📦 Fetching versions for %s...\n", packageName)
		} else {
			fmt.Printf("📦 Fetching versions for %s...\n", packageName)
		}

		result, err := client.GetPackageVersions(packageName)
		if err != nil {
			return fmt.Errorf("failed to get versions: %w", err)
		}
		printRateLimit(client)

		return printOutput(result, vdbOutput)
	},
}

// gcveCmd retrieves paginated CVEs by date range
var gcveCmd = &cobra.Command{
	Use:   "gcve",
	Short: "Get CVEs by date range",
	Long: `Retrieve a paginated list of CVEs published within a date range, with enrichment data.

Examples:
  vulnetix vdb gcve --start 2024-01-01 --end 2024-01-31
  vulnetix vdb gcve --start 2024-01-01 --end 2024-12-31 --output json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		start, _ := cmd.Flags().GetString("start")
		end, _ := cmd.Flags().GetString("end")

		if start == "" {
			return fmt.Errorf("--start is required (format: YYYY-MM-DD)")
		}
		if end == "" {
			return fmt.Errorf("--end is required (format: YYYY-MM-DD)")
		}

		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintf(os.Stderr, "📅 Fetching CVEs from %s to %s...\n", start, end)
		} else {
			fmt.Printf("📅 Fetching CVEs from %s to %s...\n", start, end)
		}

		result, err := client.GetCVEsByDateRange(start, end)
		if err != nil {
			return fmt.Errorf("failed to get CVEs: %w", err)
		}
		printRateLimit(client)

		return printOutput(result, vdbOutput)
	},
}

// ecosystemsCmd lists available ecosystems
var ecosystemsCmd = &cobra.Command{
	Use:   "ecosystems",
	Short: "List available package ecosystems",
	Long: `List all available package ecosystems in the VDB.

Examples:
  vulnetix vdb ecosystems
  vulnetix vdb ecosystems --output json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintln(os.Stderr, "🌐 Fetching available ecosystems...")
		} else {
			fmt.Println("🌐 Fetching available ecosystems...")
		}

		ecosystems, err := client.GetEcosystems()
		if err != nil {
			return fmt.Errorf("failed to get ecosystems: %w", err)
		}
		printRateLimit(client)

		if vdbOutput == "json" {
			return printOutput(map[string]interface{}{"ecosystems": ecosystems}, vdbOutput)
		}

		fmt.Printf("\n✅ Found %d ecosystems:\n\n", len(ecosystems))
		for _, eco := range ecosystems {
			fmt.Printf("  • %s (%d packages)\n", eco.Name, eco.Count)
		}

		return nil
	},
}

// productCmd retrieves product version information
var productCmd = &cobra.Command{
	Use:   "product <product-name> [version] [ecosystem]",
	Short: "Get product version information",
	Long: `Retrieve version information for a specific product.

If no version is specified, lists all available versions.
If a version is specified, retrieves detailed information for that version.
If an ecosystem is also specified, scopes the query to that ecosystem.

Examples:
  # List all versions
  vulnetix vdb product express

  # Get specific version
  vulnetix vdb product express 4.17.1

  # Get specific version scoped to ecosystem
  vulnetix vdb product express 4.17.1 npm

  # With pagination
  vulnetix vdb product express --limit 50 --offset 100`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		productName := args[0]

		// Get pagination flags
		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")

		client := newVDBClient()

		// If ecosystem is provided, get version+ecosystem info
		if len(args) > 2 {
			version := args[1]
			ecosystem := args[2]
			if vdbOutput == "json" {
				fmt.Fprintf(os.Stderr, "🔍 Fetching information for %s@%s (%s)...\n", productName, version, ecosystem)
			} else {
				fmt.Printf("🔍 Fetching information for %s@%s (%s)...\n", productName, version, ecosystem)
			}

			info, err := client.GetProductVersionEcosystem(productName, version, ecosystem)
			if err != nil {
				return fmt.Errorf("failed to get product version ecosystem: %w", err)
			}
			printRateLimit(client)

			return printOutput(info, vdbOutput)
		}

		// If version is provided, get specific version info
		if len(args) > 1 {
			version := args[1]
			if vdbOutput == "json" {
				fmt.Fprintf(os.Stderr, "🔍 Fetching information for %s@%s...\n", productName, version)
			} else {
				fmt.Printf("🔍 Fetching information for %s@%s...\n", productName, version)
			}

			info, err := client.GetProductVersion(productName, version)
			if err != nil {
				return fmt.Errorf("failed to get product version: %w", err)
			}
			printRateLimit(client)

			return printOutput(info, vdbOutput)
		}

		// Otherwise, list all versions
		if vdbOutput == "json" {
			fmt.Fprintf(os.Stderr, "📦 Fetching versions for %s...\n", productName)
		} else {
			fmt.Printf("📦 Fetching versions for %s...\n", productName)
		}

		resp, err := client.GetProductVersions(productName, limit, offset)
		if err != nil {
			return fmt.Errorf("failed to get product versions: %w", err)
		}
		printRateLimit(client)

		if vdbOutput == "json" {
			return printOutput(resp, vdbOutput)
		}

		fmt.Printf("\n✅ Found %d total versions (showing %d):\n\n", resp.Total, len(resp.Versions))
		for i, v := range resp.Versions {
			fmt.Printf("  %d. %s (%s) — %d source(s)\n", i+1, v.Version, v.Ecosystem, len(v.Sources))
		}

		if resp.HasMore {
			fmt.Printf("\n💡 More results available. Use --offset %d to see more.\n", resp.Offset+resp.Limit)
		}

		return nil
	},
}

// vulnsCmd retrieves vulnerabilities for a package
var vulnsCmd = &cobra.Command{
	Use:   "vulns <package-name>",
	Short: "Get vulnerabilities for a package",
	Long: `Retrieve all known vulnerabilities for a specific package.

Examples:
  vulnetix vdb vulns express
  vulnetix vdb vulns express --limit 50
  vulnetix vdb vulns express --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		packageName := args[0]

		// Get pagination flags
		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")

		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintf(os.Stderr, "🔒 Fetching vulnerabilities for %s...\n", packageName)
		} else {
			fmt.Printf("🔒 Fetching vulnerabilities for %s...\n", packageName)
		}

		resp, err := client.GetPackageVulnerabilities(packageName, limit, offset)
		if err != nil {
			return fmt.Errorf("failed to get vulnerabilities: %w", err)
		}
		printRateLimit(client)

		if vdbOutput == "json" {
			return printOutput(resp, vdbOutput)
		}

		// Merge both possible field names into a single list
		items := resp.Versions
		if len(items) == 0 {
			items = resp.Vulnerabilities
		}

		fmt.Printf("\n⚠️  Found %d CVE(s) across %d version(s):\n\n", resp.TotalCVEs, len(items))
		for i, v := range items {
			fmt.Printf("  %d. %s (%s) — %d source(s)\n", i+1, v.Version, v.Ecosystem, len(v.Sources))
			for _, src := range v.Sources {
				fmt.Printf("     • %s: %s\n", src.SourceTable, src.SourceID)
			}
		}
		if len(items) == 0 && resp.TotalCVEs > 0 {
			// Neither typed field captured the data — dump the raw API response
			// so no details are ever silently discarded.
			fmt.Printf("  Full API response:\n")
			return printOutput(resp.RawData, "pretty")
		}

		if resp.HasMore {
			fmt.Printf("\n💡 More results available. Use --offset %d to see more.\n", resp.Offset+resp.Limit)
		}

		return nil
	},
}

// specCmd retrieves the OpenAPI specification
var specCmd = &cobra.Command{
	Use:   "spec",
	Short: "Get the OpenAPI specification",
	Long: `Retrieve the OpenAPI specification for the VDB API.

Examples:
  vulnetix vdb spec
  vulnetix vdb spec --output json > vdb-spec.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintln(os.Stderr, "📋 Fetching OpenAPI specification...")
		} else {
			fmt.Println("📋 Fetching OpenAPI specification...")
		}

		spec, err := client.GetOpenAPISpec()
		if err != nil {
			return fmt.Errorf("failed to get spec: %w", err)
		}
		printRateLimit(client)

		return printOutput(spec, vdbOutput)
	},
}

// printRateLimit prints rate limit info from the last API call to stderr.
func printRateLimit(client *vdb.Client) {
	rl := client.LastRateLimit
	if rl == nil || !rl.Present {
		return
	}
	if rl.MinuteLimit == 0 && rl.WeekLimit == 0 {
		fmt.Fprintf(os.Stderr, "Rate limit: unlimited")
	} else {
		if rl.MinuteLimit == 0 {
			fmt.Fprintf(os.Stderr, "Rate limit: unlimited requests this minute")
		} else {
			fmt.Fprintf(os.Stderr, "Rate limit: %s/%s requests remaining this minute (resets in %s)",
				formatNumber(rl.Remaining), formatNumber(rl.MinuteLimit), formatDuration(rl.Reset))
		}
		if rl.WeekLimit == 0 {
			fmt.Fprintf(os.Stderr, " | unlimited this week")
		} else {
			fmt.Fprintf(os.Stderr, " | %s/%s this week (resets in %s)",
				formatNumber(rl.WeekRemaining), formatNumber(rl.WeekLimit), formatDuration(rl.WeekReset))
		}
	}
	fmt.Fprintln(os.Stderr)
}

// formatDuration converts seconds into a human-readable duration string.
func formatDuration(seconds int) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		m := seconds / 60
		s := seconds % 60
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm %ds", m, s)
	}
	if seconds < 86400 {
		h := seconds / 3600
		m := (seconds % 3600) / 60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh %dm", h, m)
	}
	d := seconds / 86400
	h := (seconds % 86400) / 3600
	if h == 0 {
		return fmt.Sprintf("%dd", d)
	}
	return fmt.Sprintf("%dd %dh", d, h)
}

// formatNumber formats an integer with comma separators.
func formatNumber(n int) string {
	if n < 0 {
		return "-" + formatNumber(-n)
	}
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}

// newVDBClient creates a VDB client using the loaded credentials
func newVDBClient() *vdb.Client {
	if vdbCreds != nil {
		client := vdb.NewClientFromCredentials(vdbCreds)
		if vdbBaseURL != "" && vdbBaseURL != vdb.DefaultBaseURL {
			client.BaseURL = vdbBaseURL
		}
		return client
	}
	client := vdb.NewClient(vdbOrgID, vdbSecretKey)
	if vdbBaseURL != "" {
		client.BaseURL = vdbBaseURL
	}
	return client
}

// printOutput prints the output in the specified format
func printOutput(data interface{}, format string) error {
	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(data)
	case "pretty", "":
		jsonBytes, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}
		fmt.Println(string(jsonBytes))
		return nil
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

func init() {
	// Add vdb command to root
	rootCmd.AddCommand(vdbCmd)

	// Add subcommands
	vdbCmd.AddCommand(vulnCmd)
	vdbCmd.AddCommand(ecosystemsCmd)
	vdbCmd.AddCommand(productCmd)
	vdbCmd.AddCommand(vulnsCmd)
	vdbCmd.AddCommand(specCmd)
	vdbCmd.AddCommand(exploitsCmd)
	vdbCmd.AddCommand(fixesCmd)
	vdbCmd.AddCommand(versionsCmd)
	vdbCmd.AddCommand(gcveCmd)

	// Global flags
	vdbCmd.PersistentFlags().StringVar(&vdbOrgID, "org-id", "", "Organization UUID (overrides VVD_ORG env var)")
	vdbCmd.PersistentFlags().StringVar(&vdbSecretKey, "secret", "", "Secret key (overrides VVD_SECRET env var)")
	vdbCmd.PersistentFlags().StringVar(&vdbBaseURL, "base-url", vdb.DefaultBaseURL, "VDB API base URL")
	vdbCmd.PersistentFlags().StringVarP(&vdbOutput, "output", "o", "pretty", "Output format (json, pretty)")

	// Pagination flags for applicable commands
	productCmd.Flags().Int("limit", 100, "Maximum number of results to return (default 100; use with --offset for pagination)")
	productCmd.Flags().Int("offset", 0, "Number of results to skip (for pagination)")

	vulnsCmd.Flags().Int("limit", 100, "Maximum number of results to return (default 100; use with --offset for pagination)")
	vulnsCmd.Flags().Int("offset", 0, "Number of results to skip (for pagination)")

	// gcve date range flags
	gcveCmd.Flags().String("start", "", "Start date (YYYY-MM-DD) [required]")
	gcveCmd.Flags().String("end", "", "End date (YYYY-MM-DD) [required]")
}
