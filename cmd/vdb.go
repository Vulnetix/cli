package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/internal/auth"
	"github.com/vulnetix/cli/internal/cache"
	"github.com/vulnetix/cli/internal/purl"
	"github.com/vulnetix/cli/internal/vdb"
)

var (
	vdbOrgID        string
	vdbSecretKey    string
	vdbAPIKey       string
	vdbMethod       string
	vdbBaseURL      string
	vdbOutput       string
	vdbAPIVersion   string
	vdbNoCache      bool
	vdbRefreshCache bool
	vdbCreds        *auth.Credentials
)

// vdbCmd represents the vdb command
var vdbCmd = &cobra.Command{
	Use:   "vdb",
	Short: "Interact with the Vulnetix Vulnerability Database (VDB) API",
	Long: `Access and query the Vulnetix Vulnerability Database (VDB) API.

The VDB API provides comprehensive vulnerability intelligence from multiple authoritative sources
including MITRE CVE, NIST NVD, CISA KEV, and many others.

Authentication (recommended):
  vulnetix auth login        # interactive setup — saves to ~/.vulnetix/credentials.json

Credential sources (checked in order):
  1. Command-line flags (--org-id + --api-key or --secret)
  2. Environment variables: VULNETIX_API_KEY + VULNETIX_ORG_ID (Direct API Key)
  3. Environment variables: VVD_ORG + VVD_SECRET (SigV4)
  4. Project file: .vulnetix/credentials.json
  5. Home file: ~/.vulnetix/credentials.json

Flag patterns:
  vulnetix vdb ecosystems --org-id UUID --api-key KEY      # Direct API Key
  vulnetix vdb ecosystems --org-id UUID --secret KEY        # SigV4
  vulnetix vdb ecosystems --api-version v2                  # Target API v2
  vulnetix vdb ecosystems -V v2                             # Short form

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
		return resolveVDBCredentials(true)
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
// Also serves as parent for exploits subcommands (search, sources, types)
var exploitsCmd = &cobra.Command{
	Use:   "exploits [vuln-id]",
	Short: "Get exploit intelligence for a specific vulnerability",
	Long: `Retrieve exploit intelligence for a vulnerability, aggregating data from multiple exploit
databases including ExploitDB, Metasploit modules, Nuclei templates, VulnCheck, CrowdSec, and
GitHub proof-of-concept repositories.

Accepts any supported vulnerability identifier (CVE, GHSA, PYSEC, ZDI, SNYK, and 70+ more).

Subcommands:
  search    Search exploits across CVEs with filters and pagination
  sources   List exploit intelligence sources
  types     List exploit type classifications

Examples:
  vulnetix vdb exploits CVE-2021-44228
  vulnetix vdb exploits GHSA-jfh8-3a1q-hjz9
  vulnetix vdb exploits search --severity CRITICAL --limit 10
  vulnetix vdb exploits sources
  vulnetix vdb exploits types`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return cmd.Help()
		}
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

// exploitsSearchCmd searches exploits across CVEs with filters and pagination
var exploitsSearchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search exploits across CVEs with filters and pagination",
	Long: `Search for exploits across all CVEs with filtering and pagination support.

Filters:
  --ecosystem    Package ecosystem (e.g. npm, pypi, maven)
  --source       Exploit source (exploitdb, metasploit, nuclei, vulncheck-xdb, crowdsec, github, poc)
  --severity     CVSS severity (CRITICAL, HIGH, MEDIUM, LOW, NONE)
  --in-kev       Only show CVEs in CISA KEV
  --min-epss     Minimum EPSS score (0-1)
  -q/--query     Free text search
  --sort         Sort order (recent, epss, severity, maturity)

Examples:
  vulnetix vdb exploits search --severity CRITICAL --limit 10
  vulnetix vdb exploits search --source metasploit --in-kev
  vulnetix vdb exploits search -q "log4j" --sort maturity
  vulnetix vdb exploits search --ecosystem npm --min-epss 0.9`,
	RunE: func(cmd *cobra.Command, args []string) error {
		params := vdb.ExploitSearchParams{}
		params.Ecosystem, _ = cmd.Flags().GetString("ecosystem")
		params.Source, _ = cmd.Flags().GetString("source")
		params.Severity, _ = cmd.Flags().GetString("severity")
		params.InKev, _ = cmd.Flags().GetString("in-kev")
		params.MinEpss, _ = cmd.Flags().GetString("min-epss")
		params.Query, _ = cmd.Flags().GetString("query")
		params.Sort, _ = cmd.Flags().GetString("sort")
		params.Limit, _ = cmd.Flags().GetInt("limit")
		params.Offset, _ = cmd.Flags().GetInt("offset")

		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintln(os.Stderr, "🔍 Searching exploits...")
		} else {
			fmt.Println("🔍 Searching exploits...")
		}

		result, err := client.SearchExploits(params)
		if err != nil {
			return fmt.Errorf("failed to search exploits: %w", err)
		}
		printRateLimit(client)

		return printOutput(result, vdbOutput)
	},
}

// fixesCmd retrieves fix data for a specific vulnerability
// Also serves as parent for fixes subcommands (distributions)
// With -V v2, merges registry, distributions, and source fixes in parallel
var fixesCmd = &cobra.Command{
	Use:   "fixes [vuln-id]",
	Short: "Get fix data for a specific vulnerability",
	Long: `Retrieve comprehensive fix data for a vulnerability including patches, advisories,
workarounds, KEV required actions, and AI-generated analysis.

With -V v2, fetches and merges registry fixes, distribution patches, and source fixes
from three separate V2 endpoints in parallel.

Accepts any supported vulnerability identifier (CVE, GHSA, PYSEC, ZDI, SNYK, and 70+ more).

Subcommands:
  distributions   List supported Linux distributions for fix advisories

Examples:
  vulnetix vdb fixes CVE-2021-44228
  vulnetix vdb fixes CVE-2021-44228 -V v2
  vulnetix vdb fixes distributions`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return cmd.Help()
		}
		identifier := args[0]

		// V2 mode: merge three fix endpoints
		if normalizeAPIVersion(vdbAPIVersion) == "/v2" {
			if vdbOutput == "json" {
				fmt.Fprintf(os.Stderr, "🔧 Fetching V2 fix data for %s...\n", identifier)
			} else {
				fmt.Printf("🔧 Fetching V2 fix data for %s...\n", identifier)
			}

			merged, err := v2FixesMerged(identifier, cmd)
			if err != nil {
				return fmt.Errorf("failed to get V2 fixes: %w", err)
			}
			return printOutput(merged, vdbOutput)
		}

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
// Also serves as parent for gcve subcommands (issuances)
var gcveCmd = &cobra.Command{
	Use:   "gcve [--start --end]",
	Short: "Get CVEs by date range",
	Long: `Retrieve a paginated list of CVEs published within a date range, with enrichment data.

Subcommands:
  issuances   List GCVE issuance identifiers by calendar month

Examples:
  vulnetix vdb gcve --start 2024-01-01 --end 2024-01-31
  vulnetix vdb gcve --start 2024-01-01 --end 2024-12-31 --output json
  vulnetix vdb gcve issuances --year 2025 --month 3`,
	RunE: func(cmd *cobra.Command, args []string) error {
		start, _ := cmd.Flags().GetString("start")
		end, _ := cmd.Flags().GetString("end")

		if start == "" || end == "" {
			return cmd.Help()
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
	Use:   "issuances",
	Short: "List GCVE issuance identifiers by calendar month",
	Long: `Retrieve a paginated list of GCVE issuance identifiers (GCVE-VVD-YYYY-NNNN) published in a given calendar month.

Examples:
  vulnetix vdb gcve issuances --year 2025 --month 3
  vulnetix vdb gcve issuances --year 2025 --month 3 --output json
  vulnetix vdb gcve issuances --year 2025 --month 3 --limit 50 --offset 100`,
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

The /spec endpoint is public and does not require authentication.

Examples:
  vulnetix vdb spec
  vulnetix vdb spec --output json > vdb-spec.json`,
	// Override parent's PersistentPreRunE — spec is public, no auth required
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		_ = resolveVDBCredentials(false)
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if vdbOutput == "json" {
			fmt.Fprintln(os.Stderr, "📋 Fetching OpenAPI specification...")
		} else {
			fmt.Println("📋 Fetching OpenAPI specification...")
		}

		// If credentials are available, use the authenticated client
		if vdbCreds != nil && vdbCreds.OrgID != "" {
			client := newVDBClient()
			spec, err := client.GetOpenAPISpec()
			if err != nil {
				return fmt.Errorf("failed to get spec: %w", err)
			}
			printRateLimit(client)
			return printOutput(spec, vdbOutput)
		}

		// No credentials — use direct HTTP GET (spec is public)
		baseURL := vdbBaseURL
		if baseURL == "" {
			baseURL = vdb.DefaultBaseURL
		}
		apiVer := vdb.DefaultAPIVersion
		if vdbAPIVersion != "" {
			apiVer = normalizeAPIVersion(vdbAPIVersion)
		}
		specURL := baseURL + apiVer + "/spec"

		resp, err := http.Get(specURL) //nolint:noctx
		if err != nil {
			return fmt.Errorf("failed to fetch spec: %w", err)
		}
		defer resp.Body.Close()

		var spec map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&spec); err != nil {
			return fmt.Errorf("failed to parse spec: %w", err)
		}

		return printOutput(spec, vdbOutput)
	},
}

// printRateLimit prints rate limit and cache status from the last API call to stderr.
func printRateLimit(client *vdb.Client) {
	if client.LastCacheStatus != "" {
		status := strings.ToUpper(client.LastCacheStatus)
		// Normalize CloudFront format ("Hit from cloudfront" → "HIT")
		switch {
		case status == "LOCAL":
			fmt.Fprintf(os.Stderr, "Cache: LOCAL (no network request)\n")
			return // No rate limit consumed
		case status == "REVALIDATED":
			fmt.Fprintf(os.Stderr, "Cache: REVALIDATED (304 Not Modified)\n")
		case strings.Contains(status, "HIT"):
			status = "HIT"
			fmt.Fprintf(os.Stderr, "Cache: %s\n", status)
		case strings.Contains(status, "MISS"):
			status = "MISS"
			fmt.Fprintf(os.Stderr, "Cache: %s\n", status)
		default:
			fmt.Fprintf(os.Stderr, "Cache: %s\n", status)
		}
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

// normalizeAPIVersion normalizes user input into a clean version path prefix.
// e.g. "V2" → "/v2", "/v2/" → "/v2", "v2" → "/v2"
func normalizeAPIVersion(input string) string {
	s := strings.ToLower(strings.Trim(input, "/"))
	return "/" + s
}

// newVDBClient creates a VDB client using the loaded credentials
func newVDBClient() *vdb.Client {
	var client *vdb.Client
	if vdbCreds != nil {
		client = vdb.NewClientFromCredentials(vdbCreds)
		if vdbBaseURL != "" && vdbBaseURL != vdb.DefaultBaseURL {
			client.BaseURL = vdbBaseURL
		}
	} else {
		client = vdb.NewClient(vdbOrgID, vdbSecretKey)
		if vdbBaseURL != "" {
			client.BaseURL = vdbBaseURL
		}
	}
	if vdbAPIVersion != "" {
		client.APIVersion = normalizeAPIVersion(vdbAPIVersion)
	}

	// Initialize disk cache (non-fatal if it fails)
	client.NoCache = vdbNoCache
	client.RefreshCache = vdbRefreshCache
	if dc, err := cache.NewDiskCache(); err == nil {
		client.Cache = dc
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

// metricsCmd is the parent for metrics subcommands
var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Vulnerability metric intelligence",
	Long: `Vulnerability metric and scoring type information.

Subcommands:
  types   List vulnerability metric/scoring types

Examples:
  vulnetix vdb metrics types`,
}

// metricTypesCmd lists vulnerability metric/scoring types
var metricTypesCmd = &cobra.Command{
	Use:   "types",
	Short: "List vulnerability metric/scoring types",
	Long: `List all vulnerability metric and scoring types tracked by the VDB.

Examples:
  vulnetix vdb metrics types
  vulnetix vdb metrics types --output json`,
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
	Use:   "sources",
	Short: "List exploit intelligence sources",
	Long: `List all exploit intelligence sources tracked by the VDB.

Examples:
  vulnetix vdb exploits sources
  vulnetix vdb exploits sources --output json`,
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
	Use:   "types",
	Short: "List exploit type classifications",
	Long: `List all exploit type classifications tracked by the VDB.

Examples:
  vulnetix vdb exploits types
  vulnetix vdb exploits types --output json`,
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
	Use:   "distributions",
	Short: "List supported Linux distributions for fix advisories",
	Long: `List all supported Linux distributions for fix advisories in the VDB.

Examples:
  vulnetix vdb fixes distributions
  vulnetix vdb fixes distributions --output json`,
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
		_ = resolveVDBCredentials(false)
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
			Source string `json:"source"`
			Status string `json:"status"`
		}
		authResult := authInfo{Method: "none", Source: "none", Status: "not configured"}
		if vdbCreds != nil && vdbCreds.OrgID != "" {
			authResult.OrgID = vdbCreds.OrgID
			authResult.Method = string(vdbCreds.Method)
			// Determine credential source
			if vdbAPIKey != "" || vdbSecretKey != "" {
				authResult.Source = "flags"
			} else {
				authResult.Source = auth.CredentialSource()
			}
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
			APIVersion string `json:"api_version"`
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
				APIVersion: client.APIVersion,
				OASSpecURL: client.BaseURL + client.APIVersion + "/spec",
			},
			API:  apiHealth,
			Auth: authResult,
		}

		return printOutput(result, vdbOutput)
	},
}

// resolveVDBCredentials builds vdbCreds from flags, env vars, or config files.
// When errorOnMissing is false, missing credentials are silently ignored (for status).
func resolveVDBCredentials(errorOnMissing bool) error {
	// Reject conflicting flags
	if vdbSecretKey != "" && vdbAPIKey != "" {
		return fmt.Errorf("cannot use both --secret and --api-key; choose one authentication method")
	}

	// Determine method from flags
	hasFlags := vdbOrgID != "" && (vdbSecretKey != "" || vdbAPIKey != "")
	if hasFlags {
		// Explicit --method validation
		if vdbMethod != "" {
			m, err := auth.ValidateMethod(vdbMethod)
			if err != nil {
				return err
			}
			switch m {
			case auth.DirectAPIKey:
				if vdbAPIKey == "" {
					return fmt.Errorf("--method apikey requires --api-key")
				}
			case auth.SigV4:
				if vdbSecretKey == "" {
					return fmt.Errorf("--method sigv4 requires --secret")
				}
			}
		}

		// Auto-detect method from which flag was provided
		if vdbAPIKey != "" {
			vdbCreds = &auth.Credentials{
				OrgID:  vdbOrgID,
				APIKey: vdbAPIKey,
				Method: auth.DirectAPIKey,
			}
		} else {
			vdbCreds = &auth.Credentials{
				OrgID:  vdbOrgID,
				Secret: vdbSecretKey,
				Method: auth.SigV4,
			}
		}
		return nil
	}

	// No complete flag set — fall through to stored/env credentials
	creds, err := vdb.LoadFullCredentials()
	if err != nil {
		if errorOnMissing {
			return err
		}
		return nil
	}
	vdbCreds = creds
	if vdbOrgID == "" {
		vdbOrgID = creds.OrgID
	}
	if vdbSecretKey == "" {
		vdbSecretKey = creds.Secret
	}
	return nil
}

// packagesCmd is the parent for package-related subcommands
var packagesCmd = &cobra.Command{
	Use:   "packages",
	Short: "Package search and discovery",
	Long: `Package search and discovery commands.

Subcommands:
  search   Full-text search across packages

Examples:
  vulnetix vdb packages search express
  vulnetix vdb packages search lodash --ecosystem npm`,
}

// packagesSearchCmd performs full-text search across packages
var packagesSearchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Full-text search across packages",
	Long: `Search for packages by name across all ecosystems.

Examples:
  vulnetix vdb packages search express
  vulnetix vdb packages search lodash --ecosystem npm --limit 20
  vulnetix vdb packages search log4j --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		query := args[0]
		ecosystem, _ := cmd.Flags().GetString("ecosystem")
		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")

		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintf(os.Stderr, "🔍 Searching packages for %q...\n", query)
		} else {
			fmt.Printf("🔍 Searching packages for %q...\n", query)
		}

		result, err := client.SearchPackages(query, ecosystem, limit, offset)
		if err != nil {
			return fmt.Errorf("failed to search packages: %w", err)
		}
		printRateLimit(client)

		return printOutput(result, vdbOutput)
	},
}

// cacheCmd is the parent for cache management subcommands
var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage the local VDB response cache",
	Long: `Manage the local disk cache used for VDB API responses.

Subcommands:
  clear   Remove all cached responses

Examples:
  vulnetix vdb cache clear`,
}

// cacheClearCmd removes all cached VDB responses
var cacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Remove all cached VDB API responses",
	Long: `Clear the local disk cache at ~/.vulnetix/cache/vdb/.

This forces the next API call to fetch fresh data from the server.

Examples:
  vulnetix vdb cache clear`,
	// Override parent's PersistentPreRunE — cache clear needs no auth
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		dc, err := cache.NewDiskCache()
		if err != nil {
			return fmt.Errorf("failed to open cache: %w", err)
		}
		if err := dc.Clear(); err != nil {
			return fmt.Errorf("failed to clear cache: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Cache cleared: %s\n", dc.Dir())
		return nil
	},
}

func init() {
	// Add vdb command to root
	rootCmd.AddCommand(vdbCmd)

	// Direct subcommands of vdb
	vdbCmd.AddCommand(vulnCmd)
	vdbCmd.AddCommand(ecosystemsCmd)
	vdbCmd.AddCommand(productCmd)
	vdbCmd.AddCommand(vulnsCmd)
	vdbCmd.AddCommand(specCmd)
	vdbCmd.AddCommand(exploitsCmd)
	vdbCmd.AddCommand(fixesCmd)
	vdbCmd.AddCommand(versionsCmd)
	vdbCmd.AddCommand(gcveCmd)
	vdbCmd.AddCommand(idsCmd)
	vdbCmd.AddCommand(searchCmd)
	vdbCmd.AddCommand(sourcesCmd)
	vdbCmd.AddCommand(metricsCmd)
	vdbCmd.AddCommand(packagesCmd)
	vdbCmd.AddCommand(purlCmd)
	vdbCmd.AddCommand(statusCmd)
	vdbCmd.AddCommand(cacheCmd)

	// Nested subcommands: cache → clear
	cacheCmd.AddCommand(cacheClearCmd)

	// Nested subcommands: exploits → search, sources, types
	exploitsCmd.AddCommand(exploitsSearchCmd)
	exploitsCmd.AddCommand(exploitSourcesCmd)
	exploitsCmd.AddCommand(exploitTypesCmd)

	// Nested subcommands: fixes → distributions
	fixesCmd.AddCommand(fixDistributionsCmd)

	// Nested subcommands: gcve → issuances
	gcveCmd.AddCommand(gcveIssuancesCmd)

	// Nested subcommands: metrics → types
	metricsCmd.AddCommand(metricTypesCmd)

	// Nested subcommands: packages → search
	packagesCmd.AddCommand(packagesSearchCmd)

	// Hidden aliases for backward compatibility (old hyphenated names).
	// The no-args enum commands just share RunE directly.
	// The gcve-issuances alias needs its own flag set since flags are per-command.
	vdbCmd.AddCommand(&cobra.Command{
		Use:    "exploit-sources",
		Hidden: true,
		RunE:   exploitSourcesCmd.RunE,
	})
	vdbCmd.AddCommand(&cobra.Command{
		Use:    "exploit-types",
		Hidden: true,
		RunE:   exploitTypesCmd.RunE,
	})
	vdbCmd.AddCommand(&cobra.Command{
		Use:    "fix-distributions",
		Hidden: true,
		RunE:   fixDistributionsCmd.RunE,
	})
	vdbCmd.AddCommand(&cobra.Command{
		Use:    "metric-types",
		Hidden: true,
		RunE:   metricTypesCmd.RunE,
	})
	gcveIssuancesAlias := &cobra.Command{
		Use:    "gcve-issuances",
		Hidden: true,
		RunE:   gcveIssuancesCmd.RunE,
	}
	gcveIssuancesAlias.Flags().Int("year", 0, "Publication year (4-digit) [required]")
	gcveIssuancesAlias.Flags().Int("month", 0, "Publication month 1-12 [required]")
	gcveIssuancesAlias.Flags().Int("limit", 100, "Maximum results (max 500)")
	gcveIssuancesAlias.Flags().Int("offset", 0, "Results to skip (pagination)")
	vdbCmd.AddCommand(gcveIssuancesAlias)

	// Global flags
	vdbCmd.PersistentFlags().StringVar(&vdbOrgID, "org-id", "", "Organization UUID (overrides VVD_ORG env var)")
	vdbCmd.PersistentFlags().StringVar(&vdbSecretKey, "secret", "", "SigV4 secret key (overrides VVD_SECRET env var)")
	vdbCmd.PersistentFlags().StringVar(&vdbAPIKey, "api-key", "", "Direct API key (overrides VULNETIX_API_KEY env var)")
	vdbCmd.PersistentFlags().StringVar(&vdbMethod, "method", "", "Auth method: apikey or sigv4 (auto-detected from flags if omitted)")
	vdbCmd.PersistentFlags().StringVar(&vdbBaseURL, "base-url", vdb.DefaultBaseURL, "VDB API base URL")
	vdbCmd.PersistentFlags().StringVarP(&vdbAPIVersion, "api-version", "V", "", `API version path (default "v1"; e.g. "v2")`)
	vdbCmd.PersistentFlags().StringVarP(&vdbOutput, "output", "o", "pretty", "Output format (json, pretty)")
	vdbCmd.PersistentFlags().BoolVar(&vdbNoCache, "no-cache", false, "Bypass local disk cache entirely")
	vdbCmd.PersistentFlags().BoolVar(&vdbRefreshCache, "refresh-cache", false, "Ignore cached data and fetch fresh from API (updates cache)")

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

	// gcve issuances flags
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

	// exploits search flags
	exploitsSearchCmd.Flags().String("ecosystem", "", "Filter by package ecosystem")
	exploitsSearchCmd.Flags().String("source", "", "Exploit source (exploitdb, metasploit, nuclei, vulncheck-xdb, crowdsec, github, poc)")
	exploitsSearchCmd.Flags().String("severity", "", "CVSS severity (CRITICAL, HIGH, MEDIUM, LOW, NONE)")
	exploitsSearchCmd.Flags().String("in-kev", "", "Only KEV CVEs (true/false)")
	exploitsSearchCmd.Flags().String("min-epss", "", "Minimum EPSS score (0-1)")
	exploitsSearchCmd.Flags().StringP("query", "q", "", "Free text search")
	exploitsSearchCmd.Flags().String("sort", "", "Sort order (recent, epss, severity, maturity)")
	exploitsSearchCmd.Flags().Int("limit", 100, "Maximum results (max 100)")
	exploitsSearchCmd.Flags().Int("offset", 0, "Results to skip (pagination)")

	// packages search flags
	packagesSearchCmd.Flags().String("ecosystem", "", "Filter by ecosystem")
	packagesSearchCmd.Flags().Int("limit", 100, "Maximum results")
	packagesSearchCmd.Flags().Int("offset", 0, "Results to skip (pagination)")

	// V2 context flags for fixes (used in V2 merge mode)
	fixesCmd.Flags().String("ecosystem", "", "Filter by package ecosystem (V2 only)")
	fixesCmd.Flags().String("package-name", "", "Filter by package name (V2 only)")
	fixesCmd.Flags().String("vendor", "", "Filter by vendor name (V2 only)")
	fixesCmd.Flags().String("product", "", "Filter by product name (V2 only)")
	fixesCmd.Flags().String("purl", "", "Package URL (V2 only)")
}
