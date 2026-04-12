package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/internal/analytics"
	"github.com/vulnetix/cli/pkg/auth"
	"github.com/vulnetix/cli/pkg/cache"
	"github.com/vulnetix/cli/internal/config"
	"github.com/vulnetix/cli/internal/display"
	"github.com/vulnetix/cli/internal/gitctx"
	"github.com/vulnetix/cli/internal/memory"
	"github.com/vulnetix/cli/internal/purl"
	"github.com/vulnetix/cli/pkg/tty"
	"github.com/vulnetix/cli/pkg/vdb"
	"gopkg.in/yaml.v3"
)

var (
	vdbOrgID         string
	vdbSecretKey     string
	vdbAPIKey        string
	vdbMethod        string
	vdbBaseURL       string
	vdbOutput        string
	vdbAPIVersion    string
	vdbNoCache       bool
	vdbRefreshCache  bool
	vdbNoCommunity   bool
	vdbCommunityMode bool
	vdbCreds         *auth.Credentials
	vdbCompact       bool
	vdbComfortable   bool
	vdbSparse        bool
	vdbHighlight     string

	// Context flags for Claude Code Plugin memory management
	vdbPackageManager string
	vdbManifestFormat string
	vdbGitLocalDir    string
	vdbGitBranch      string
	vdbGithubOrg      string
	vdbGithubRepo     string
	vdbGithubPR       string
	vdbRemoteURL      string
	vdbRemoteBranch   string
	vdbCommitterName  string
	vdbCommitterEmail string

	// Environment/memory control flags
	vdbIgnoreEnv   bool
	vdbContextJSON string

	// Runtime state (set in PersistentPreRunE, consumed in PersistentPostRunE)
	vdbEnvContext  *memory.EnvironmentContext
	vdbMemory      *memory.Memory
	vdbVulnetixDir string
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
  6. Unauthenticated Community (built-in, --no-community to disable)

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
		// Initialize display context with correct output mode
		mode := display.ModeText
		if vdbOutput == "json" || vdbOutput == "yaml" {
			mode = display.ModeJSON
		}
		initDisplayContext(cmd, mode)

		if err := validateOutputFlags(); err != nil {
			return err
		}
		if err := resolveVDBCredentials(true); err != nil {
			return err
		}

		// Track VDB subcommand usage
		analytics.TrackVDBQuery(cmd.Name(), vdbAPIVersion)

		// Environment context gathering and memory loading (non-fatal)
		if !disableMemory {
			cwd, _ := os.Getwd()
			gc := gitctx.Collect(cwd)

			if !vdbIgnoreEnv {
				vdbEnvContext = gitCtxToEnvContext(gc)
			} else {
				vdbEnvContext = &memory.EnvironmentContext{
					Platform: string(config.DetectPlatform()),
				}
			}
			applyContextJSONOverrides(vdbEnvContext, vdbContextJSON)
			applyContextFlagOverrides(vdbEnvContext)

			vdbVulnetixDir = resolveVulnetixDir(gc)
			vdbMemory, _ = memory.Load(vdbVulnetixDir)
		}

		return nil
	},
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		// Save memory (non-fatal)
		if !disableMemory && vdbMemory != nil && vdbVulnetixDir != "" {
			vdbMemory.UpdateEnvironment(vdbEnvContext)
			if err := memory.Save(vdbVulnetixDir, vdbMemory); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not update memory: %v\n", err)
			}
		}

		// Replicate rootCmd's PersistentPostRun (update check notification)
		if updateCheckResult != nil {
			select {
			case msg := <-updateCheckResult:
				if msg != "" {
					fmt.Fprint(os.Stderr, msg)
				}
			default:
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
		ctx := display.FromCommand(cmd)

		client := newVDBClient()

		ctx.Logger.Infof("🔍 Fetching information for %s...", cveID)

		cveInfo, err := client.GetCVE(cveID)
		if err != nil {
			var nfe *vdb.NotFoundError
			if errors.As(err, &nfe) {
				ctx.Logger.Warn(fmt.Sprintf("⚠ Vulnerability %q was not found in the database.", cveID))
				ctx.Logger.Info("  This identifier has been flagged for review by Vulnetix admins.")
				return nil
			}
			return fmt.Errorf("failed to get CVE: %w", err)
		}
		printRateLimit(client)

		if !disableMemory && vdbMemory != nil {
			vdbMemory.RecordVulnLookup(cveID, cveInfo.Data)
		}
		recordVDBQuery("vuln", cveID)

		if vdbOutput == "pretty" || vdbOutput == "" {
			return ctx.Render(cveInfo.Data, display.RenderVulnDetail)
		}
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
		ctx := display.FromCommand(cmd)

		client := newVDBClient()

		ctx.Logger.Infof("💥 Fetching exploit intelligence for %s...", identifier)

		result, err := client.GetExploits(identifier)
		if err != nil {
			return fmt.Errorf("failed to get exploits: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("exploits", identifier)

		if vdbOutput == "pretty" || vdbOutput == "" {
			return ctx.Render(result, display.RenderExploits)
		}
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

		ctx := display.FromCommand(cmd)
		client := newVDBClient()

		ctx.Logger.Info("🔍 Searching exploits...")

		result, err := client.SearchExploits(params)
		if err != nil {
			return fmt.Errorf("failed to search exploits: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("exploits search", params.Query)

		if vdbOutput == "pretty" || vdbOutput == "" {
			return ctx.Render(result, display.RenderExploitSearch)
		}
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
			vdbLog(cmd).Infof("🔧 Fetching V2 fix data for %s...", identifier)

			merged, err := v2FixesMerged(identifier, cmd)
			if err != nil {
				return fmt.Errorf("failed to get V2 fixes: %w", err)
			}
			recordVDBQuery("fixes", identifier)
			return vdbRender(cmd, merged, display.RenderFixes)
		}

		client := newVDBClient()

		vdbLog(cmd).Infof("🔧 Fetching fix data for %s...", identifier)

		result, err := client.GetCVEFixes(identifier)
		if err != nil {
			return fmt.Errorf("failed to get fixes: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("fixes", identifier)

		return vdbRender(cmd, result, display.RenderFixes)
	},
}

// timelineCmd retrieves the vulnerability lifecycle timeline
var timelineCmd = &cobra.Command{
	Use:   "timeline <vuln-id>",
	Short: "Get vulnerability lifecycle timeline",
	Long: `Retrieve the vulnerability lifecycle timeline including CVE dates, exploits,
scoring history, patches, and advisories.

With -V v2, also returns source transparency data (sources{}).

Event types: source, exploit, score-change, patch, advisory, scorecard

Accepts any supported vulnerability identifier (CVE, GHSA, PYSEC, ZDI, SNYK, and 70+ more).

Examples:
  vulnetix vdb timeline CVE-2021-44228
  vulnetix vdb timeline CVE-2021-44228 --include exploit,source
  vulnetix vdb timeline CVE-2021-44228 --exclude score-change
  vulnetix vdb timeline CVE-2021-44228 --scores-limit 10
  vulnetix vdb timeline CVE-2021-44228 -V v2 --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		identifier := args[0]
		include, _ := cmd.Flags().GetString("include")
		exclude, _ := cmd.Flags().GetString("exclude")
		dates, _ := cmd.Flags().GetString("dates")
		scoresLimit, _ := cmd.Flags().GetInt("scores-limit")

		client := newVDBClient()
		vdbLog(cmd).Infof("📅 Fetching timeline for %s...", identifier)

		// V2 mode: use v2 endpoint with source transparency
		if normalizeAPIVersion(vdbAPIVersion) == "/v2" {
			result, err := client.V2Timeline(identifier, vdb.V2TimelineParams{
				Include:     include,
				Exclude:     exclude,
				Dates:       dates,
				ScoresLimit: scoresLimit,
			})
			if err != nil {
				return fmt.Errorf("failed to get timeline: %w", err)
			}
			printRateLimit(client)
			recordVDBQuery("timeline", identifier)
			return vdbRender(cmd, result, display.RenderTimeline)
		}

		// V1 mode (default)
		result, err := client.GetCVETimeline(identifier, vdb.TimelineParams{
			Include:     include,
			Exclude:     exclude,
			Dates:       dates,
			ScoresLimit: scoresLimit,
		})
		if err != nil {
			return fmt.Errorf("failed to get timeline: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("timeline", identifier)
		return vdbRender(cmd, result, display.RenderTimeline)
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

		vdbLog(cmd).Infof("📦 Fetching versions for %s...", packageName)

		result, err := client.GetPackageVersions(packageName)
		if err != nil {
			return fmt.Errorf("failed to get versions: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("versions", packageName)

		return vdbRender(cmd, result, display.RenderVersions)
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

		vdbLog(cmd).Infof("📅 Fetching CVEs from %s to %s...", start, end)

		result, err := client.GetCVEsByDateRange(start, end)
		if err != nil {
			return fmt.Errorf("failed to get CVEs: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("gcve", start+" to "+end)

		return vdbRender(cmd, result, display.RenderGenericMap)
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

		vdbLog(cmd).Infof("📋 Fetching GCVE issuances for %d/%02d...", year, month)

		resp, err := client.GetGCVEIssuances(year, month, limit, offset)
		if err != nil {
			return fmt.Errorf("failed to get GCVE issuances: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("gcve issuances", fmt.Sprintf("%d/%02d", year, month))

		return vdbRender(cmd, display.ToMap(resp), func(data interface{}, ctx *display.Context) string {
			return display.RenderIdentifiers(data, ctx, "GCVE issuances")
		})
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

		vdbLog(cmd).Info("🌐 Fetching available ecosystems...")

		ecosystems, err := client.GetEcosystems()
		if err != nil {
			return fmt.Errorf("failed to get ecosystems: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("ecosystems", "")

		// Convert typed slice to []interface{} with map entries for the display layer
		ecoSlice := make([]interface{}, len(ecosystems))
		for i, e := range ecosystems {
			ecoSlice[i] = map[string]interface{}{
				"name":  e.Name,
				"count": e.Count,
			}
		}

		return vdbRender(cmd, map[string]interface{}{"ecosystems": ecoSlice}, func(data interface{}, ctx *display.Context) string {
			if m, ok := data.(map[string]interface{}); ok {
				if ecos, ok := m["ecosystems"].([]interface{}); ok {
					return display.RenderEcosystems(ecos, ctx)
				}
			}
			return display.RenderGenericMap(data, ctx)
		})
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
			vdbLog(cmd).Infof("🔍 Fetching information for %s@%s (%s)...", productName, version, ecosystem)

			info, err := client.GetProductVersionEcosystem(productName, version, ecosystem)
			if err != nil {
				var nfe *vdb.NotFoundError
				if errors.As(err, &nfe) {
					vdbLog(cmd).Warn(fmt.Sprintf("⚠ Product %q (version %s, ecosystem %s) was not found in the database.", productName, version, ecosystem))
					vdbLog(cmd).Info("  This identifier has been flagged for review by Vulnetix admins.")
					return nil
				}
				return fmt.Errorf("failed to get product version ecosystem: %w", err)
			}
			printRateLimit(client)
			recordVDBQuery("product", productName+" "+version+" "+ecosystem)

			if isEmptyResult(info) {
				vdbLog(cmd).Warn(fmt.Sprintf("⚠ Product %q (version %s, ecosystem %s) was not found in the database.", productName, version, ecosystem))
				vdbLog(cmd).Info("  This identifier has been flagged for review by Vulnetix admins.")
				return nil
			}

			return vdbRender(cmd, info, display.RenderGenericMap)
		}

		// If version is provided, get specific version info
		if len(args) > 1 {
			version := args[1]
			vdbLog(cmd).Infof("🔍 Fetching information for %s@%s...", productName, version)

			info, err := client.GetProductVersion(productName, version)
			if err != nil {
				var nfe *vdb.NotFoundError
				if errors.As(err, &nfe) {
					vdbLog(cmd).Warn(fmt.Sprintf("⚠ Product %q (version %s) was not found in the database.", productName, version))
					vdbLog(cmd).Info("  This identifier has been flagged for review by Vulnetix admins.")
					return nil
				}
				return fmt.Errorf("failed to get product version: %w", err)
			}
			printRateLimit(client)
			recordVDBQuery("product", productName+" "+version)

			if isEmptyResult(info) {
				vdbLog(cmd).Warn(fmt.Sprintf("⚠ Product %q (version %s) was not found in the database.", productName, version))
				vdbLog(cmd).Info("  This identifier has been flagged for review by Vulnetix admins.")
				return nil
			}

			return vdbRender(cmd, info, display.RenderGenericMap)
		}

		// Otherwise, list all versions
		vdbLog(cmd).Infof("📦 Fetching versions for %s...", productName)

		resp, err := client.GetProductVersions(productName, limit, offset)
		if err != nil {
			var nfe *vdb.NotFoundError
			if errors.As(err, &nfe) {
				vdbLog(cmd).Warn(fmt.Sprintf("⚠ Product %q was not found in the database.", productName))
				vdbLog(cmd).Info("  This identifier has been flagged for review by Vulnetix admins.")
				return nil
			}
			return fmt.Errorf("failed to get product versions: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("product", productName)

		if resp.Total == 0 {
			vdbLog(cmd).Warn(fmt.Sprintf("⚠ Product %q was not found in the database.", productName))
			vdbLog(cmd).Info("  This identifier has been flagged for review by Vulnetix admins.")
			return nil
		}

		return vdbRender(cmd, display.ToMap(resp), display.RenderProductVersions)
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

		vdbLog(cmd).Infof("🔒 Fetching vulnerabilities for %s...", packageName)

		resp, err := client.GetPackageVulnerabilities(packageName, limit, offset)
		if err != nil {
			var nfe *vdb.NotFoundError
			if errors.As(err, &nfe) {
				vdbLog(cmd).Warn(fmt.Sprintf("⚠ Package %q was not found in the database.", packageName))
				vdbLog(cmd).Info("  This identifier has been flagged for review by Vulnetix admins.")
				return nil
			}
			return fmt.Errorf("failed to get vulnerabilities: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("vulns", packageName)

		if resp.TotalCVEs == 0 && resp.Total == 0 {
			vdbLog(cmd).Warn(fmt.Sprintf("⚠ Package %q was not found in the database.", packageName))
			vdbLog(cmd).Info("  This identifier has been flagged for review by Vulnetix admins.")
			return nil
		}

		return vdbRender(cmd, display.ToMap(resp), display.RenderPackageVulns)
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
		mode := display.ModeText
		if vdbOutput == "json" || vdbOutput == "yaml" {
			mode = display.ModeJSON
		}
		initDisplayContext(cmd, mode)
		if err := validateOutputFlags(); err != nil {
			return err
		}
		_ = resolveVDBCredentials(false)
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := display.FromCommand(cmd)
		ctx.Logger.Info("📋 Fetching OpenAPI specification...")

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
// Suppressed when --silent is active.
func printRateLimit(client *vdb.Client) {
	if silent {
		return
	}
	if vdbCommunityMode {
		fmt.Fprintln(os.Stderr, "Auth: Unauthenticated Community (run 'vulnetix auth login' for higher rate limits)")
	} else if client.UsingFallback {
		fmt.Fprintln(os.Stderr, "Auth: Switched to Community (quota exhausted — run 'vulnetix auth login' for higher quota)")
	}
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

	// Plan tier
	if rl.Plan != "" {
		fmt.Fprintf(os.Stderr, "Plan: %s", rl.Plan)
		if rl.SoftLimits {
			fmt.Fprintf(os.Stderr, " (soft limits)")
		}
		fmt.Fprintf(os.Stderr, " | ")
	}

	// Daily quota
	if rl.DayLimit == 0 && rl.Remaining < 0 {
		fmt.Fprintf(os.Stderr, "Rate limit: unlimited")
	} else {
		resetSecs := rl.Reset - int(time.Now().Unix())
		if resetSecs < 0 {
			resetSecs = 0
		}
		fmt.Fprintf(os.Stderr, "Rate limit: %s/%s req/day remaining (resets in %s)",
			formatNumber(rl.Remaining), formatNumber(rl.DayLimit), formatDuration(resetSecs))
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
	if dc, err := cache.NewDiskCache(version); err == nil {
		client.Cache = dc
	}

	// Populate community fallback unless disabled or already using community credentials
	if !vdbNoCommunity && !auth.IsCommunity(vdbCreds) {
		client.FallbackCreds = auth.CommunityCredentials()
	}

	return client
}

// vdbRender outputs data: text renderer in pretty mode, printOutput otherwise.
func vdbRender(cmd *cobra.Command, data interface{}, textFn func(data interface{}, ctx *display.Context) string) error {
	if vdbOutput == "pretty" || vdbOutput == "" {
		ctx := display.FromCommand(cmd)
		return ctx.Render(data, textFn)
	}
	return printOutput(data, vdbOutput)
}

// vdbLog returns the display logger for a command.
func vdbLog(cmd *cobra.Command) *display.Logger {
	return display.FromCommand(cmd).Logger
}

// isEmptyResult returns true when a map-typed API response has total == 0.
func isEmptyResult(m map[string]interface{}) bool {
	if t, ok := m["total"]; ok {
		switch v := t.(type) {
		case float64:
			return v == 0
		case int:
			return v == 0
		}
	}
	return false
}

// printOutput prints the output in the specified format
func printOutput(data interface{}, format string) error {
	switch format {
	case "json":
		indent := resolveIndent()
		jsonBytes, err := json.MarshalIndent(data, "", indent)
		if err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}
		output := string(jsonBytes)

		if (vdbHighlight == "dark" || vdbHighlight == "light") && tty.StdoutIsTerminal() {
			highlighted, err := highlightJSON(output, vdbHighlight)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Warning: syntax highlighting failed, falling back to plain output")
				fmt.Println(output)
				return nil
			}
			fmt.Print(highlighted)
		} else {
			fmt.Println(output)
		}
		return nil
	case "yaml":
		yamlBytes, err := yaml.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to format YAML output: %w", err)
		}
		fmt.Print(string(yamlBytes))
		return nil
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

// resolveIndent returns the JSON indent string based on the active preset flag.
func resolveIndent() string {
	switch {
	case vdbCompact:
		return "  "
	case vdbSparse:
		return "        "
	default:
		return "    "
	}
}

// highlightJSON applies terminal syntax highlighting to a JSON string.
func highlightJSON(jsonStr string, theme string) (string, error) {
	lexer := lexers.Get("json")
	if lexer == nil {
		return "", fmt.Errorf("JSON lexer not available")
	}
	lexer = chroma.Coalesce(lexer)

	var styleName string
	switch theme {
	case "dark":
		styleName = "monokai"
	case "light":
		styleName = "github"
	default:
		return jsonStr, nil
	}

	style := styles.Get(styleName)
	formatter := formatters.Get("terminal256")

	iterator, err := lexer.Tokenise(nil, jsonStr)
	if err != nil {
		return "", err
	}

	var buf strings.Builder
	err = formatter.Format(&buf, style, iterator)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// validateOutputFlags checks that indent and highlight flags are only used with --output json.
func validateOutputFlags() error {
	if vdbOutput != "json" {
		if vdbCompact || vdbSparse || vdbComfortable {
			return fmt.Errorf("--compact, --comfortable, and --sparse are only valid with --output json")
		}
		if vdbHighlight != "none" && vdbHighlight != "" {
			return fmt.Errorf("--highlight is only valid with --output json")
		}
	}
	if vdbHighlight != "" && vdbHighlight != "none" && vdbHighlight != "dark" && vdbHighlight != "light" {
		return fmt.Errorf("--highlight must be one of: dark, light, none")
	}
	return nil
}

// gitCtxToEnvContext converts a gitctx.GitContext to a memory.EnvironmentContext.
func gitCtxToEnvContext(gc *gitctx.GitContext) *memory.EnvironmentContext {
	env := &memory.EnvironmentContext{
		Platform: string(config.DetectPlatform()),
	}
	if gc == nil {
		return env
	}
	env.GitLocalDir = gc.RepoRootPath
	env.GitBranch = gc.CurrentBranch
	env.GitCommit = gc.CurrentCommit
	if len(gc.RemoteURLs) > 0 {
		env.GitRemoteURL = gc.RemoteURLs[0]
	}
	env.CommitterName = gc.HeadCommitAuthor
	env.CommitterEmail = gc.HeadCommitEmail
	return env
}

// applyContextJSONOverrides parses --context JSON and overlays values onto env.
func applyContextJSONOverrides(env *memory.EnvironmentContext, jsonStr string) {
	if jsonStr == "" {
		return
	}
	var overrides map[string]string
	if err := json.Unmarshal([]byte(jsonStr), &overrides); err != nil {
		fmt.Fprintf(os.Stderr, "warning: invalid --context JSON: %v\n", err)
		return
	}
	if v, ok := overrides["platform"]; ok {
		env.Platform = v
	}
	if v, ok := overrides["git_local_dir"]; ok {
		env.GitLocalDir = v
	}
	if v, ok := overrides["git_branch"]; ok {
		env.GitBranch = v
	}
	if v, ok := overrides["git_commit"]; ok {
		env.GitCommit = v
	}
	if v, ok := overrides["remote_url"]; ok {
		env.GitRemoteURL = v
	}
	if v, ok := overrides["remote_branch"]; ok {
		env.GitRemoteBranch = v
	}
	if v, ok := overrides["committer_name"]; ok {
		env.CommitterName = v
	}
	if v, ok := overrides["committer_email"]; ok {
		env.CommitterEmail = v
	}
	if v, ok := overrides["github_org"]; ok {
		env.GithubOrg = v
	}
	if v, ok := overrides["github_repo"]; ok {
		env.GithubRepo = v
	}
	if v, ok := overrides["github_pr"]; ok {
		env.GithubPR = v
	}
	if v, ok := overrides["package_manager"]; ok {
		env.PackageManager = v
	}
	if v, ok := overrides["manifest_format"]; ok {
		env.ManifestFormat = v
	}
}

// applyContextFlagOverrides applies explicit CLI flags (highest priority).
func applyContextFlagOverrides(env *memory.EnvironmentContext) {
	if vdbPackageManager != "" {
		env.PackageManager = vdbPackageManager
	}
	if vdbManifestFormat != "" {
		env.ManifestFormat = vdbManifestFormat
	}
	if vdbGitLocalDir != "" {
		env.GitLocalDir = vdbGitLocalDir
	}
	if vdbGitBranch != "" {
		env.GitBranch = vdbGitBranch
	}
	if vdbGithubOrg != "" {
		env.GithubOrg = vdbGithubOrg
	}
	if vdbGithubRepo != "" {
		env.GithubRepo = vdbGithubRepo
	}
	if vdbGithubPR != "" {
		env.GithubPR = vdbGithubPR
	}
	if vdbRemoteURL != "" {
		env.GitRemoteURL = vdbRemoteURL
	}
	if vdbRemoteBranch != "" {
		env.GitRemoteBranch = vdbRemoteBranch
	}
	if vdbCommitterName != "" {
		env.CommitterName = vdbCommitterName
	}
	if vdbCommitterEmail != "" {
		env.CommitterEmail = vdbCommitterEmail
	}
}

// resolveVulnetixDir returns the path to the .vulnetix directory.
// If inside a git repo, uses the repo root. Otherwise, uses ~/.vulnetix.
func resolveVulnetixDir(gc *gitctx.GitContext) string {
	if gc != nil && gc.RepoRootPath != "" {
		return filepath.Join(gc.RepoRootPath, ".vulnetix")
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ".vulnetix"
	}
	return filepath.Join(homeDir, ".vulnetix")
}

// recordVDBQuery appends a VDB query entry to the in-memory log.
// No-op when memory is disabled.
func recordVDBQuery(command string, args string) {
	if disableMemory || vdbMemory == nil {
		return
	}
	vdbMemory.RecordVDBQuery(memory.VDBQuery{
		Command:    command,
		Args:       args,
		APIVersion: vdbAPIVersion,
	})
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

		vdbLog(cmd).Info("📡 Fetching vulnerability data sources...")

		result, err := client.GetSources()
		if err != nil {
			return fmt.Errorf("failed to get sources: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("sources", "")

		return vdbRender(cmd, result, func(data interface{}, ctx *display.Context) string {
			return display.RenderSimpleList(data, ctx, "sources")
		})
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

		vdbLog(cmd).Info("📊 Fetching vulnerability metric types...")

		result, err := client.GetMetricTypes()
		if err != nil {
			return fmt.Errorf("failed to get metric types: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("metrics types", "")

		return vdbRender(cmd, result, func(data interface{}, ctx *display.Context) string {
			return display.RenderSimpleList(data, ctx, "metric types")
		})
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

		vdbLog(cmd).Info("🔎 Fetching exploit intelligence sources...")

		result, err := client.GetExploitSources()
		if err != nil {
			return fmt.Errorf("failed to get exploit sources: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("exploits sources", "")

		return vdbRender(cmd, result, func(data interface{}, ctx *display.Context) string {
			return display.RenderSimpleList(data, ctx, "exploit sources")
		})
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

		vdbLog(cmd).Info("💣 Fetching exploit type classifications...")

		result, err := client.GetExploitTypes()
		if err != nil {
			return fmt.Errorf("failed to get exploit types: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("exploits types", "")

		return vdbRender(cmd, result, func(data interface{}, ctx *display.Context) string {
			return display.RenderSimpleList(data, ctx, "exploit types")
		})
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

		vdbLog(cmd).Info("🐧 Fetching supported fix distributions...")

		result, err := client.GetFixDistributions()
		if err != nil {
			return fmt.Errorf("failed to get fix distributions: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("fixes distributions", "")

		return vdbRender(cmd, result, func(data interface{}, ctx *display.Context) string {
			return display.RenderSimpleList(data, ctx, "distributions")
		})
	},
}

// trafficFiltersCmd retrieves IDS/IPS traffic filter rules for a vulnerability
var trafficFiltersCmd = &cobra.Command{
	Use:   "traffic-filters <vuln-id>",
	Short: "Get IDS/IPS traffic filter rules (Snort) for a vulnerability",
	Long: `Retrieve IDS/IPS traffic filter rules (Snort signatures) mapped to a specific
vulnerability identifier. Rules include detection signatures, MITRE ATT&CK mappings,
severity classifications, and full raw rule text.

Only CVE, GHSA, and CNVD identifiers are supported for traffic filter lookups.

Supported identifier formats:
  CVE-2021-44228         MITRE / NVD
  GHSA-jfh8-3a1q-hjz9   GitHub Security Advisory
  CNVD-2024-02713        China National Vulnerability DB

Examples:
  vulnetix vdb traffic-filters CVE-2021-44228
  vulnetix vdb traffic-filters GHSA-jfh8-3a1q-hjz9
  vulnetix vdb traffic-filters CVE-2021-44228 -o json
  vulnetix vdb traffic-filters CVE-2021-44228 --limit 10
  vulnetix vdb traffic-filters CVE-2021-44228 -V v2`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		identifier := args[0]
		ctx := display.FromCommand(cmd)

		trafficFilterRe := regexp.MustCompile(`(?i)^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|CNVD-\d{4}-\d{4,})$`)
		if !trafficFilterRe.MatchString(identifier) {
			return fmt.Errorf("invalid identifier %q — traffic-filters supports CVE, GHSA, and CNVD formats only\n  Examples: CVE-2021-44228, GHSA-jfh8-3a1q-hjz9, CNVD-2024-02713", identifier)
		}

		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")

		client := newVDBClient()

		ctx.Logger.Infof("🛡️ Fetching traffic filter rules for %s...", identifier)

		result, err := client.GetTrafficFilters(identifier, limit, offset)
		if err != nil {
			var nfe *vdb.NotFoundError
			if errors.As(err, &nfe) {
				ctx.Logger.Warn(fmt.Sprintf("⚠ Vulnerability %q was not found in the database.", identifier))
				return nil
			}
			return fmt.Errorf("failed to get traffic filters: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("traffic-filters", identifier)

		return vdbRender(cmd, result, display.RenderTrafficFilters)
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

		vdbLog(cmd).Infof("🔍 Fetching CVE identifiers for %d/%02d...", year, month)

		resp, err := client.GetIdentifiersByMonth(year, month, limit, offset)
		if err != nil {
			return fmt.Errorf("failed to get identifiers: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("ids", fmt.Sprintf("%d/%02d", year, month))

		return vdbRender(cmd, display.ToMap(resp), func(data interface{}, ctx *display.Context) string {
			return display.RenderIdentifiers(data, ctx, "CVE identifiers")
		})
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

		vdbLog(cmd).Infof("🔍 Searching CVE identifiers with prefix %q...", prefix)

		resp, err := client.SearchIdentifiers(prefix, limit, offset)
		if err != nil {
			return fmt.Errorf("failed to search identifiers: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("search", prefix)

		return vdbRender(cmd, display.ToMap(resp), func(data interface{}, ctx *display.Context) string {
			return display.RenderIdentifiers(data, ctx, "matching CVE identifiers")
		})
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
				vdbLog(cmd).Infof("🔍 Fetching %s@%s (%s)...", packageName, p.Version, ecosystem)
				info, err := client.GetProductVersionEcosystem(packageName, p.Version, ecosystem)
				if err != nil {
					var nfe *vdb.NotFoundError
					if errors.As(err, &nfe) {
						vdbLog(cmd).Warn(fmt.Sprintf("⚠ Product %q (version %s, ecosystem %s) was not found in the database.", packageName, p.Version, ecosystem))
						vdbLog(cmd).Info("  This identifier has been flagged for review by Vulnetix admins.")
						return nil
					}
					return fmt.Errorf("failed to get product version ecosystem: %w", err)
				}
				printRateLimit(client)
				recordVDBQuery("purl", args[0])
				if isEmptyResult(info) {
					vdbLog(cmd).Warn(fmt.Sprintf("⚠ Product %q (version %s, ecosystem %s) was not found in the database.", packageName, p.Version, ecosystem))
					vdbLog(cmd).Info("  This identifier has been flagged for review by Vulnetix admins.")
					return nil
				}
				return vdbRender(cmd, info, display.RenderGenericMap)
			}

			vdbLog(cmd).Infof("🔍 Fetching %s@%s...", packageName, p.Version)
			info, err := client.GetProductVersion(packageName, p.Version)
			if err != nil {
				var nfe *vdb.NotFoundError
				if errors.As(err, &nfe) {
					vdbLog(cmd).Warn(fmt.Sprintf("⚠ Product %q (version %s) was not found in the database.", packageName, p.Version))
					vdbLog(cmd).Info("  This identifier has been flagged for review by Vulnetix admins.")
					return nil
				}
				return fmt.Errorf("failed to get product version: %w", err)
			}
			printRateLimit(client)
			recordVDBQuery("purl", args[0])
			if isEmptyResult(info) {
				vdbLog(cmd).Warn(fmt.Sprintf("⚠ Product %q (version %s) was not found in the database.", packageName, p.Version))
				vdbLog(cmd).Info("  This identifier has been flagged for review by Vulnetix admins.")
				return nil
			}
			return vdbRender(cmd, info, display.RenderGenericMap)
		}

		// No version
		showVulns, _ := cmd.Flags().GetBool("vulns")
		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")

		if showVulns {
			vdbLog(cmd).Infof("🔒 Fetching vulnerabilities for %s...", packageName)
			resp, err := client.GetPackageVulnerabilities(packageName, limit, offset)
			if err != nil {
				var nfe *vdb.NotFoundError
				if errors.As(err, &nfe) {
					vdbLog(cmd).Warn(fmt.Sprintf("⚠ Package %q was not found in the database.", packageName))
					vdbLog(cmd).Info("  This identifier has been flagged for review by Vulnetix admins.")
					return nil
				}
				return fmt.Errorf("failed to get vulnerabilities: %w", err)
			}
			printRateLimit(client)
			recordVDBQuery("purl", args[0])
			if resp.TotalCVEs == 0 && resp.Total == 0 {
				vdbLog(cmd).Warn(fmt.Sprintf("⚠ Package %q was not found in the database.", packageName))
				vdbLog(cmd).Info("  This identifier has been flagged for review by Vulnetix admins.")
				return nil
			}
			return vdbRender(cmd, display.ToMap(resp), display.RenderPackageVulns)
		}

		vdbLog(cmd).Infof("📦 Fetching versions for %s...", packageName)
		resp, err := client.GetProductVersions(packageName, limit, offset)
		if err != nil {
			var nfe *vdb.NotFoundError
			if errors.As(err, &nfe) {
				vdbLog(cmd).Warn(fmt.Sprintf("⚠ Product %q was not found in the database.", packageName))
				vdbLog(cmd).Info("  This identifier has been flagged for review by Vulnetix admins.")
				return nil
			}
			return fmt.Errorf("failed to get product versions: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("purl", args[0])
		if resp.Total == 0 {
			vdbLog(cmd).Warn(fmt.Sprintf("⚠ Product %q was not found in the database.", packageName))
			vdbLog(cmd).Info("  This identifier has been flagged for review by Vulnetix admins.")
			return nil
		}
		return vdbRender(cmd, display.ToMap(resp), display.RenderProductVersions)
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
		mode := display.ModeText
		if vdbOutput == "json" || vdbOutput == "yaml" {
			mode = display.ModeJSON
		}
		initDisplayContext(cmd, mode)
		if err := validateOutputFlags(); err != nil {
			return err
		}
		_ = resolveVDBCredentials(false)
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		vdbLog(cmd).Info("🔍 Checking VDB API status...")

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
			if vdbCommunityMode {
				authResult.Method = string(vdbCreds.Method)
				authResult.Source = "Unauthenticated Community"
				authResult.Status = "ok (community)"
			} else {
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

		return vdbRender(cmd, result, display.RenderStatus)
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
		// Community fallback: VDB-only, last-resort
		if !vdbNoCommunity {
			vdbCreds = auth.CommunityCredentials()
			vdbCommunityMode = true
			return nil
		}
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

		vdbLog(cmd).Infof("🔍 Searching packages for %q...", query)

		result, err := client.SearchPackages(query, ecosystem, limit, offset)
		if err != nil {
			var nfe *vdb.NotFoundError
			if errors.As(err, &nfe) {
				vdbLog(cmd).Warn(fmt.Sprintf("⚠ No packages matching %q were found in the database.", query))
				vdbLog(cmd).Info("  This query has been flagged for review by Vulnetix admins.")
				return nil
			}
			return fmt.Errorf("failed to search packages: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("packages search", query)

		if isEmptyResult(result) {
			vdbLog(cmd).Warn(fmt.Sprintf("⚠ No packages matching %q were found in the database.", query))
			vdbLog(cmd).Info("  This query has been flagged for review by Vulnetix admins.")
			return nil
		}

		return vdbRender(cmd, result, func(data interface{}, ctx *display.Context) string {
			return display.RenderPackagesSearch(data, ctx)
		})
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
	Long: `Clear the local disk cache at ~/.vulnetix/cache/vdb/vX.Y/ for the current CLI version.

This forces the next API call to fetch fresh data from the server.

Examples:
  vulnetix vdb cache clear`,
	// Override parent's PersistentPreRunE — cache clear needs no auth
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		initDisplayContext(cmd, display.ModeText)
		return validateOutputFlags()
	},
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		dc, err := cache.NewDiskCache(version)
		if err != nil {
			return fmt.Errorf("failed to open cache: %w", err)
		}
		if err := dc.Clear(); err != nil {
			return fmt.Errorf("failed to clear cache: %w", err)
		}
		vdbLog(cmd).Infof("Cache cleared: %s", dc.Dir())
		return nil
	},
}

// summaryCmd retrieves global database statistics
var summaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Get global VDB database statistics",
	Long: `Retrieve all-time statistics for the entire Vulnetix Vulnerability Database.

Shows database coverage, severity distribution, enrichment rates, exploit and
malware counts, and the top 10 CWEs and vendors by CVE volume.

Examples:
  vulnetix vdb summary
  vulnetix vdb summary --output json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()

		vdbLog(cmd).Info("📊 Fetching VDB database summary...")

		result, err := client.GetSummary()
		if err != nil {
			return fmt.Errorf("failed to get summary: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("summary", "")

		return vdbRender(cmd, result, display.RenderSummary)
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
	vdbCmd.AddCommand(timelineCmd)
	vdbCmd.AddCommand(versionsCmd)
	vdbCmd.AddCommand(gcveCmd)
	vdbCmd.AddCommand(idsCmd)
	vdbCmd.AddCommand(searchCmd)
	vdbCmd.AddCommand(sourcesCmd)
	vdbCmd.AddCommand(metricsCmd)
	vdbCmd.AddCommand(packagesCmd)
	vdbCmd.AddCommand(purlCmd)
	vdbCmd.AddCommand(statusCmd)
	vdbCmd.AddCommand(summaryCmd)
	vdbCmd.AddCommand(trafficFiltersCmd)
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
	vdbCmd.PersistentFlags().StringVarP(&vdbOutput, "output", "o", "pretty", "Output format (json, yaml, pretty)")
	vdbCmd.PersistentFlags().BoolVar(&vdbNoCache, "no-cache", false, "Bypass local disk cache entirely")
	vdbCmd.PersistentFlags().BoolVar(&vdbRefreshCache, "refresh-cache", false, "Ignore cached data and fetch fresh from API (updates cache)")
	vdbCmd.PersistentFlags().BoolVar(&vdbNoCommunity, "no-community", false, "Disable community fallback credentials (require explicit authentication)")

	// JSON output formatting flags (only active with --output json)
	vdbCmd.PersistentFlags().BoolVar(&vdbCompact, "compact", false, "2-space indent (--output json only)")
	vdbCmd.PersistentFlags().BoolVar(&vdbComfortable, "comfortable", false, "4-space indent (default for --output json)")
	vdbCmd.PersistentFlags().BoolVar(&vdbSparse, "sparse", false, "8-space indent (--output json only)")
	vdbCmd.PersistentFlags().StringVar(&vdbHighlight, "highlight", "none", "Syntax highlighting: dark, light, none (--output json only)")
	_ = vdbCmd.RegisterFlagCompletionFunc("method", cobra.FixedCompletions([]string{"apikey", "sigv4"}, cobra.ShellCompDirectiveNoFileComp))
	_ = vdbCmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{"json", "yaml", "pretty"}, cobra.ShellCompDirectiveNoFileComp))
	_ = vdbCmd.RegisterFlagCompletionFunc("api-version", cobra.FixedCompletions([]string{"v1", "v2"}, cobra.ShellCompDirectiveNoFileComp))
	_ = vdbCmd.RegisterFlagCompletionFunc("highlight", cobra.FixedCompletions([]string{"dark", "light", "none"}, cobra.ShellCompDirectiveNoFileComp))
	vdbCmd.MarkFlagsMutuallyExclusive("comfortable", "compact", "sparse")

	// Context flags for Claude Code Plugin memory management.
	// These enrich the memory file with project context so the plugin can track
	// vulnerabilities per-repo, per-branch, and per-package-manager.
	vdbCmd.PersistentFlags().StringVar(&vdbPackageManager, "package-manager", "",
		"Package manager in use (e.g. npm, pip, cargo). Enriches memory context. Claude Code Plugin SKILLs should pass this flag to associate queries with a package manager.")
	vdbCmd.PersistentFlags().StringVar(&vdbManifestFormat, "manifest-format", "",
		"Manifest file format (e.g. package.json, requirements.txt). Enriches memory context. Claude Code Plugin SKILLs should pass this flag to associate queries with a manifest format.")
	vdbCmd.PersistentFlags().StringVar(&vdbGitLocalDir, "git-local-dir", "",
		"Local git repository path. Enriches memory context. Claude Code Plugin SKILLs should pass this flag to scope memory to a specific repository.")
	vdbCmd.PersistentFlags().StringVar(&vdbGitBranch, "git-branch", "",
		"Current git branch name. Enriches memory context. Claude Code Plugin SKILLs should pass this flag to scope memory to a specific branch.")
	vdbCmd.PersistentFlags().StringVar(&vdbGithubOrg, "github-org", "",
		"GitHub organization name. Enriches memory context. Claude Code Plugin SKILLs should pass this flag for GitHub-hosted repositories.")
	vdbCmd.PersistentFlags().StringVar(&vdbGithubRepo, "github-repo", "",
		"GitHub repository name. Enriches memory context. Claude Code Plugin SKILLs should pass this flag for GitHub-hosted repositories.")
	vdbCmd.PersistentFlags().StringVar(&vdbGithubPR, "github-pr", "",
		"GitHub pull request number. Enriches memory context. Claude Code Plugin SKILLs should pass this flag when operating in a PR context.")
	vdbCmd.PersistentFlags().StringVar(&vdbRemoteURL, "remote-url", "",
		"Git remote URL. Enriches memory context. Claude Code Plugin SKILLs should pass this flag for remote tracking.")
	vdbCmd.PersistentFlags().StringVar(&vdbRemoteBranch, "remote-branch", "",
		"Git remote tracking branch. Enriches memory context. Claude Code Plugin SKILLs should pass this flag for remote tracking.")
	vdbCmd.PersistentFlags().StringVar(&vdbCommitterName, "committer-name", "",
		"Git committer name. Enriches memory context. Claude Code Plugin SKILLs should pass this flag for commit attribution.")
	vdbCmd.PersistentFlags().StringVar(&vdbCommitterEmail, "committer-email", "",
		"Git committer email. Enriches memory context. Claude Code Plugin SKILLs should pass this flag for commit attribution.")

	// Environment and context control flags
	vdbCmd.PersistentFlags().BoolVar(&vdbIgnoreEnv, "ignore-env", false,
		"Disable automatic environment/git context gathering while keeping memory updates enabled")
	vdbCmd.PersistentFlags().StringVar(&vdbContextJSON, "context", "",
		`JSON string of context overrides (e.g. --context '{"git_branch":"main","committer_email":"x@y.com"}'). Overrides auto-gathered values but is overridden by explicit flags.`)

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
	_ = exploitsSearchCmd.RegisterFlagCompletionFunc("source", cobra.FixedCompletions([]string{"exploitdb", "metasploit", "nuclei", "vulncheck-xdb", "crowdsec", "github", "poc"}, cobra.ShellCompDirectiveNoFileComp))
	_ = exploitsSearchCmd.RegisterFlagCompletionFunc("severity", cobra.FixedCompletions([]string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}, cobra.ShellCompDirectiveNoFileComp))
	_ = exploitsSearchCmd.RegisterFlagCompletionFunc("sort", cobra.FixedCompletions([]string{"recent", "epss", "severity", "maturity"}, cobra.ShellCompDirectiveNoFileComp))

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

	// traffic-filters flags
	trafficFiltersCmd.Flags().Int("limit", 100, "Maximum results (max 500)")
	trafficFiltersCmd.Flags().Int("offset", 0, "Results to skip (pagination)")

	// Timeline flags
	timelineCmd.Flags().String("include", "", "Comma-separated event types to include (source,exploit,score-change,patch,advisory,scorecard)")
	timelineCmd.Flags().String("exclude", "", "Comma-separated event types to exclude")
	timelineCmd.Flags().String("dates", "", "CVE date fields: published,modified,reserved (default: all)")
	timelineCmd.Flags().Int("scores-limit", 30, "Max score-change events (max 365)")
	_ = timelineCmd.RegisterFlagCompletionFunc("dates", cobra.FixedCompletions([]string{"published", "modified", "reserved"}, cobra.ShellCompDirectiveNoFileComp))
}
