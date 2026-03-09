package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/internal/auth"
	"github.com/vulnetix/cli/internal/purl"
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

// gcveIssuancesCmd lists GCVE issuance identifiers by calendar month
var gcveIssuancesCmd = &cobra.Command{
	Use:   "gcve-issuances",
	Short: "List GCVE issuance identifiers by calendar month",
	Long: `Retrieve a paginated list of GCVE issuance identifiers (GCVE-VVD-YYYY-NNNN) published in a given calendar month.

Examples:
  vulnetix vdb gcve-issuances --year 2025 --month 3
  vulnetix vdb gcve-issuances --year 2025 --month 3 --output json
  vulnetix vdb gcve-issuances --year 2025 --month 3 --limit 50 --offset 100`,
	RunE: func(cmd *cobra.Command, args []string) error {
		year, _ := cmd.Flags().GetInt("year")
		month, _ := cmd.Flags().GetInt("month")
		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")

		if year == 0 {
			return fmt.Errorf("--year is required")
		}
		if month == 0 {
			return fmt.Errorf("--month is required")
		}
		if month < 1 || month > 12 {
			return fmt.Errorf("--month must be between 1 and 12")
		}

		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintf(os.Stderr, "📋 Fetching GCVE issuances for %d/%02d...\n", year, month)
		} else {
			fmt.Printf("📋 Fetching GCVE issuances for %d/%02d...\n", year, month)
		}

		resp, err := client.GetGCVEIssuances(year, month, limit, offset)
		if err != nil {
			return fmt.Errorf("failed to get GCVE issuances: %w", err)
		}
		printRateLimit(client)

		if vdbOutput != "json" {
			fmt.Printf("Found %d GCVE issuances (showing %d-%d):\n", resp.Total, offset+1, offset+len(resp.Identifiers))
			for _, id := range resp.Identifiers {
				fmt.Printf("  %s (cveId: %s)\n", id.GcveID, id.CveID)
			}
			if resp.HasMore {
				fmt.Printf("\nMore results available. Use --offset %d to see the next page.\n", offset+limit)
			}
			return nil
		}

		return printOutput(resp, vdbOutput)
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

// printRateLimit prints rate limit and cache status from the last API call to stderr.
func printRateLimit(client *vdb.Client) {
	if client.LastCacheStatus != "" {
		fmt.Fprintf(os.Stderr, "Cache: %s\n", strings.ToUpper(client.LastCacheStatus))
	}
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

// sourcesCmd lists vulnerability data sources
var sourcesCmd = &cobra.Command{
	Use:   "sources",
	Short: "List vulnerability data sources",
	Long: `List all vulnerability data sources tracked by the VDB.

Examples:
  vulnetix vdb sources
  vulnetix vdb sources --output json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintln(os.Stderr, "📡 Fetching vulnerability data sources...")
		} else {
			fmt.Println("📡 Fetching vulnerability data sources...")
		}

		result, err := client.GetSources()
		if err != nil {
			return fmt.Errorf("failed to get sources: %w", err)
		}
		printRateLimit(client)

		return printOutput(result, vdbOutput)
	},
}

// metricTypesCmd lists vulnerability metric/scoring types
var metricTypesCmd = &cobra.Command{
	Use:   "metric-types",
	Short: "List vulnerability metric/scoring types",
	Long: `List all vulnerability metric and scoring types tracked by the VDB.

Examples:
  vulnetix vdb metric-types
  vulnetix vdb metric-types --output json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintln(os.Stderr, "📊 Fetching vulnerability metric types...")
		} else {
			fmt.Println("📊 Fetching vulnerability metric types...")
		}

		result, err := client.GetMetricTypes()
		if err != nil {
			return fmt.Errorf("failed to get metric types: %w", err)
		}
		printRateLimit(client)

		return printOutput(result, vdbOutput)
	},
}

// exploitSourcesCmd lists exploit intelligence sources
var exploitSourcesCmd = &cobra.Command{
	Use:   "exploit-sources",
	Short: "List exploit intelligence sources",
	Long: `List all exploit intelligence sources tracked by the VDB.

Examples:
  vulnetix vdb exploit-sources
  vulnetix vdb exploit-sources --output json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintln(os.Stderr, "🔎 Fetching exploit intelligence sources...")
		} else {
			fmt.Println("🔎 Fetching exploit intelligence sources...")
		}

		result, err := client.GetExploitSources()
		if err != nil {
			return fmt.Errorf("failed to get exploit sources: %w", err)
		}
		printRateLimit(client)

		return printOutput(result, vdbOutput)
	},
}

// exploitTypesCmd lists exploit type classifications
var exploitTypesCmd = &cobra.Command{
	Use:   "exploit-types",
	Short: "List exploit type classifications",
	Long: `List all exploit type classifications tracked by the VDB.

Examples:
  vulnetix vdb exploit-types
  vulnetix vdb exploit-types --output json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintln(os.Stderr, "💣 Fetching exploit type classifications...")
		} else {
			fmt.Println("💣 Fetching exploit type classifications...")
		}

		result, err := client.GetExploitTypes()
		if err != nil {
			return fmt.Errorf("failed to get exploit types: %w", err)
		}
		printRateLimit(client)

		return printOutput(result, vdbOutput)
	},
}

// fixDistributionsCmd lists supported Linux distributions for fix advisories
var fixDistributionsCmd = &cobra.Command{
	Use:   "fix-distributions",
	Short: "List supported Linux distributions for fix advisories",
	Long: `List all supported Linux distributions for fix advisories in the VDB.

Examples:
  vulnetix vdb fix-distributions
  vulnetix vdb fix-distributions --output json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintln(os.Stderr, "🐧 Fetching supported fix distributions...")
		} else {
			fmt.Println("🐧 Fetching supported fix distributions...")
		}

		result, err := client.GetFixDistributions()
		if err != nil {
			return fmt.Errorf("failed to get fix distributions: %w", err)
		}
		printRateLimit(client)

		return printOutput(result, vdbOutput)
	},
}

// idsCmd lists CVE identifiers published in a given calendar month
var idsCmd = &cobra.Command{
	Use:   "ids <year> <month>",
	Short: "List CVE identifiers published in a calendar month",
	Long: `Retrieve a paginated list of distinct CVE identifiers published in the given calendar month.

Examples:
  vulnetix vdb ids 2024 3
  vulnetix vdb ids 2024 3 --limit 50
  vulnetix vdb ids 2024 3 --output json`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		year, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid year: %s", args[0])
		}
		month, err := strconv.Atoi(args[1])
		if err != nil || month < 1 || month > 12 {
			return fmt.Errorf("invalid month: %s (must be 1-12)", args[1])
		}

		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")

		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintf(os.Stderr, "🔍 Fetching CVE identifiers for %d/%02d...\n", year, month)
		} else {
			fmt.Printf("🔍 Fetching CVE identifiers for %d/%02d...\n", year, month)
		}

		resp, err := client.GetIdentifiersByMonth(year, month, limit, offset)
		if err != nil {
			return fmt.Errorf("failed to get identifiers: %w", err)
		}
		printRateLimit(client)

		if vdbOutput == "json" {
			return printOutput(resp, vdbOutput)
		}

		fmt.Printf("Found %d CVE identifiers (showing %d-%d):\n", resp.Total, offset+1, offset+len(resp.Identifiers))
		for _, id := range resp.Identifiers {
			fmt.Println(" ", id)
		}
		if resp.HasMore {
			fmt.Printf("\nMore results available. Use --offset %d to see the next page.\n", offset+limit)
		}
		return nil
	},
}

// searchCmd searches CVE identifiers by prefix
var searchCmd = &cobra.Command{
	Use:   "search <prefix>",
	Short: "Search CVE identifiers by prefix",
	Long: `Search for CVE identifiers matching a given prefix (case-insensitive).

Examples:
  vulnetix vdb search CVE-2024-1
  vulnetix vdb search CVE-2024-1 --limit 50
  vulnetix vdb search CVE-2024-1 --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		prefix := args[0]
		if len(prefix) < 3 {
			return fmt.Errorf("prefix must be at least 3 characters")
		}
		if len(prefix) > 50 {
			return fmt.Errorf("prefix must be at most 50 characters")
		}

		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")

		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintf(os.Stderr, "🔍 Searching CVE identifiers with prefix %q...\n", prefix)
		} else {
			fmt.Printf("🔍 Searching CVE identifiers with prefix %q...\n", prefix)
		}

		resp, err := client.SearchIdentifiers(prefix, limit, offset)
		if err != nil {
			return fmt.Errorf("failed to search identifiers: %w", err)
		}
		printRateLimit(client)

		if vdbOutput == "json" {
			return printOutput(resp, vdbOutput)
		}

		fmt.Printf("Found %d matching CVE identifiers (showing %d-%d):\n", resp.Total, offset+1, offset+len(resp.Identifiers))
		for _, id := range resp.Identifiers {
			fmt.Println(" ", id)
		}
		if resp.HasMore {
			fmt.Printf("\nMore results available. Use --offset %d to see the next page.\n", offset+limit)
		}
		return nil
	},
}

// purlCmd queries the VDB using a Package URL (PURL) string
var purlCmd = &cobra.Command{
	Use:   "purl <purl-string>",
	Short: "Query VDB using a Package URL (PURL)",
	Long: `Query the VDB API using a standard Package URL (PURL) string.

The PURL is parsed to extract the package name, version, and ecosystem, then the
appropriate VDB API endpoint is called automatically.

Dispatch logic:
  - Version + known ecosystem  → product version+ecosystem lookup
  - Version + unknown ecosystem → product version lookup
  - No version + --vulns       → package vulnerabilities
  - No version (default)       → list product versions

Examples:
  vulnetix vdb purl "pkg:npm/express@4.17.1"
  vulnetix vdb purl "pkg:maven/org.apache.commons/commons-lang3@3.12.0"
  vulnetix vdb purl "pkg:pypi/requests" --vulns
  vulnetix vdb purl "pkg:golang/github.com/go-chi/chi/v5@5.0.8" -o json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := purl.Parse(args[0])
		if err != nil {
			return fmt.Errorf("failed to parse PURL: %w", err)
		}

		packageName := p.PackageName()
		client := newVDBClient()

		// Has version → product lookup
		if p.Version != "" {
			ecosystem, knownEco := purl.EcosystemForType(p.Type)
			if knownEco {
				if vdbOutput == "json" {
					fmt.Fprintf(os.Stderr, "🔍 Fetching %s@%s (%s)...\n", packageName, p.Version, ecosystem)
				} else {
					fmt.Printf("🔍 Fetching %s@%s (%s)...\n", packageName, p.Version, ecosystem)
				}
				info, err := client.GetProductVersionEcosystem(packageName, p.Version, ecosystem)
				if err != nil {
					return fmt.Errorf("failed to get product version ecosystem: %w", err)
				}
				printRateLimit(client)
				return printOutput(info, vdbOutput)
			}

			if vdbOutput == "json" {
				fmt.Fprintf(os.Stderr, "🔍 Fetching %s@%s...\n", packageName, p.Version)
			} else {
				fmt.Printf("🔍 Fetching %s@%s...\n", packageName, p.Version)
			}
			info, err := client.GetProductVersion(packageName, p.Version)
			if err != nil {
				return fmt.Errorf("failed to get product version: %w", err)
			}
			printRateLimit(client)
			return printOutput(info, vdbOutput)
		}

		// No version
		showVulns, _ := cmd.Flags().GetBool("vulns")
		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")

		if showVulns {
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
			return printOutput(resp, vdbOutput)
		}

		if vdbOutput == "json" {
			fmt.Fprintf(os.Stderr, "📦 Fetching versions for %s...\n", packageName)
		} else {
			fmt.Printf("📦 Fetching versions for %s...\n", packageName)
		}
		resp, err := client.GetProductVersions(packageName, limit, offset)
		if err != nil {
			return fmt.Errorf("failed to get product versions: %w", err)
		}
		printRateLimit(client)
		return printOutput(resp, vdbOutput)
	},
}

// statusCmd checks API health and displays CLI/auth metadata
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check API health and display CLI metadata",
	Long: `Check the VDB API health endpoint and display a combined status report including:
  - CLI version, commit, build date, Go version, and platform
  - OAS (OpenAPI) specification URL
  - API health from the /health endpoint
  - Authentication status (method, org ID, verified OK/error)

Examples:
  vulnetix vdb status
  vulnetix vdb status --output json`,
	Args: cobra.NoArgs,
	// Own PersistentPreRunE overrides parent vdbCmd's — soft-loads creds (no error if absent)
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if vdbOrgID == "" || vdbSecretKey == "" {
			creds, err := vdb.LoadFullCredentials()
			if err == nil {
				vdbCreds = creds
				if vdbOrgID == "" {
					vdbOrgID = creds.OrgID
				}
				if vdbSecretKey == "" {
					vdbSecretKey = creds.Secret
				}
			}
			// If err != nil: no credentials found — continue without them
		} else {
			vdbCreds = &auth.Credentials{
				OrgID:  vdbOrgID,
				Secret: vdbSecretKey,
				Method: auth.SigV4,
			}
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if vdbOutput == "json" {
			fmt.Fprintln(os.Stderr, "🔍 Checking VDB API status...")
		} else {
			fmt.Println("🔍 Checking VDB API status...")
		}

		client := newVDBClient()

		// Check API health (unauthenticated)
		apiHealth, _ := client.GetHealth()

		// Determine auth status
		type authInfo struct {
			Method string `json:"method"`
			OrgID  string `json:"org_id,omitempty"`
			Status string `json:"status"`
		}
		authResult := authInfo{Method: "none", Status: "not configured"}
		if vdbCreds != nil && vdbCreds.OrgID != "" {
			authResult.OrgID = vdbCreds.OrgID
			authResult.Method = string(vdbCreds.Method)
			if err := verifyCredentials(vdbCreds); err != nil {
				authResult.Status = fmt.Sprintf("error: %s", err)
			} else {
				authResult.Status = "ok"
			}
		}

		type cliInfo struct {
			Version    string `json:"version"`
			Commit     string `json:"commit"`
			BuildDate  string `json:"build_date"`
			GoVersion  string `json:"go_version"`
			Platform   string `json:"platform"`
			OASSpecURL string `json:"oas_spec_url"`
		}
		type statusOutput struct {
			CLI  cliInfo                `json:"cli"`
			API  map[string]interface{} `json:"api"`
			Auth authInfo               `json:"auth"`
		}

		result := statusOutput{
			CLI: cliInfo{
				Version:    version,
				Commit:     commit,
				BuildDate:  buildDate,
				GoVersion:  runtime.Version(),
				Platform:   runtime.GOOS + "/" + runtime.GOARCH,
				OASSpecURL: client.BaseURL + "/spec",
			},
			API:  apiHealth,
			Auth: authResult,
		}

		return printOutput(result, vdbOutput)
	},
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
	vdbCmd.AddCommand(gcveIssuancesCmd)
	vdbCmd.AddCommand(idsCmd)
	vdbCmd.AddCommand(searchCmd)
	vdbCmd.AddCommand(sourcesCmd)
	vdbCmd.AddCommand(metricTypesCmd)
	vdbCmd.AddCommand(exploitSourcesCmd)
	vdbCmd.AddCommand(exploitTypesCmd)
	vdbCmd.AddCommand(fixDistributionsCmd)
	vdbCmd.AddCommand(purlCmd)
	vdbCmd.AddCommand(statusCmd)

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

	// purl flags
	purlCmd.Flags().Bool("vulns", false, "Show vulnerabilities instead of versions (only when PURL has no version)")
	purlCmd.Flags().Int("limit", 100, "Maximum number of results to return (default 100; use with --offset for pagination)")
	purlCmd.Flags().Int("offset", 0, "Number of results to skip (for pagination)")

	// gcve date range flags
	gcveCmd.Flags().String("start", "", "Start date (YYYY-MM-DD) [required]")
	gcveCmd.Flags().String("end", "", "End date (YYYY-MM-DD) [required]")

	// gcve-issuances flags
	gcveIssuancesCmd.Flags().Int("year", 0, "Publication year (4-digit) [required]")
	gcveIssuancesCmd.Flags().Int("month", 0, "Publication month 1-12 [required]")
	gcveIssuancesCmd.Flags().Int("limit", 100, "Maximum results (max 500)")
	gcveIssuancesCmd.Flags().Int("offset", 0, "Results to skip (pagination)")

	// ids flags
	idsCmd.Flags().Int("limit", 100, "Maximum results (max 500)")
	idsCmd.Flags().Int("offset", 0, "Results to skip (pagination)")

	// search flags
	searchCmd.Flags().Int("limit", 100, "Maximum results (max 500)")
	searchCmd.Flags().Int("offset", 0, "Results to skip (pagination)")
}
