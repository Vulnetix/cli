package cmd

import (
	"fmt"
	"sync"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/internal/display"
	"github.com/vulnetix/cli/pkg/vdb"
)

// requireV2 checks that -V v2 was specified
func requireV2(cmdName string) error {
	if normalizeAPIVersion(vdbAPIVersion) != "/v2" {
		return fmt.Errorf("this command requires -V v2\n\nUsage: vulnetix vdb %s <vuln-id> -V v2", cmdName)
	}
	return nil
}

// buildV2QueryParams constructs V2QueryParams from command flags
func buildV2QueryParams(cmd *cobra.Command) vdb.V2QueryParams {
	var p vdb.V2QueryParams
	p.Ecosystem, _ = cmd.Flags().GetString("ecosystem")
	p.PackageName, _ = cmd.Flags().GetString("package-name")
	p.Vendor, _ = cmd.Flags().GetString("vendor")
	p.Product, _ = cmd.Flags().GetString("product")
	p.Purl, _ = cmd.Flags().GetString("purl")
	p.Limit, _ = cmd.Flags().GetInt("limit")
	p.Offset, _ = cmd.Flags().GetInt("offset")
	return p
}

// addV2ContextFlags adds common V2 context filter flags
func addV2ContextFlags(cmd *cobra.Command) {
	cmd.Flags().String("ecosystem", "", "Filter by package ecosystem")
	cmd.Flags().String("package-name", "", "Filter by package name")
}

// addV2PaginationFlags adds limit/offset pagination flags to a V2 command
func addV2PaginationFlags(cmd *cobra.Command) {
	cmd.Flags().Int("limit", 100, "Maximum results per page")
	cmd.Flags().Int("offset", 0, "Pagination offset")
}

// v2WorkaroundsCmd retrieves workaround data for a vulnerability
var v2WorkaroundsCmd = &cobra.Command{
	Use:   "workarounds <vuln-id>",
	Short: "Get workaround information for a vulnerability (V2)",
	Long: `Retrieve workaround information for a vulnerability from the V2 API.

Requires -V v2.

Examples:
  vulnetix vdb workarounds CVE-2021-44228 -V v2
  vulnetix vdb workarounds CVE-2021-44228 -V v2 --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireV2("workarounds"); err != nil {
			return err
		}

		client := newVDBClient()
		vdbLog(cmd).Infof("🔧 Fetching workarounds for %s...", args[0])

		result, err := client.V2Workarounds(args[0])
		if err != nil {
			return fmt.Errorf("failed to get workarounds: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("workarounds", args[0])
		return vdbRender(cmd, result, display.RenderWorkarounds)
	},
}

// v2AdvisoriesCmd retrieves advisory data for a vulnerability
var v2AdvisoriesCmd = &cobra.Command{
	Use:   "advisories <vuln-id>",
	Short: "Get advisory data for a vulnerability (V2)",
	Long: `Retrieve advisory data for a vulnerability from the V2 API.

Requires -V v2.

Examples:
  vulnetix vdb advisories CVE-2021-44228 -V v2
  vulnetix vdb advisories CVE-2021-44228 -V v2 --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireV2("advisories"); err != nil {
			return err
		}

		client := newVDBClient()
		vdbLog(cmd).Infof("📋 Fetching advisories for %s...", args[0])

		result, err := client.V2Advisories(args[0])
		if err != nil {
			return fmt.Errorf("failed to get advisories: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("advisories", args[0])
		return vdbRender(cmd, result, display.RenderAdvisories)
	},
}

// v2CweCmd is the parent for CWE-related subcommands
var v2CweCmd = &cobra.Command{
	Use:   "cwe",
	Short: "CWE-related vulnerability intelligence (V2)",
}

// v2CweGuidanceCmd retrieves CWE-based guidance for a vulnerability
var v2CweGuidanceCmd = &cobra.Command{
	Use:   "guidance <vuln-id>",
	Short: "Get CWE-based guidance for a vulnerability (V2)",
	Long: `Retrieve CWE-based remediation guidance for a vulnerability from the V2 API.

Requires -V v2.

Examples:
  vulnetix vdb cwe guidance CVE-2021-44228 -V v2
  vulnetix vdb cwe guidance CVE-2021-44228 -V v2 --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireV2("cwe guidance"); err != nil {
			return err
		}

		client := newVDBClient()
		vdbLog(cmd).Infof("📖 Fetching CWE guidance for %s...", args[0])

		result, err := client.V2CweGuidance(args[0])
		if err != nil {
			return fmt.Errorf("failed to get CWE guidance: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("cwe guidance", args[0])
		return vdbRender(cmd, result, display.RenderCweGuidance)
	},
}

// v2KevCmd retrieves CISA KEV data for a vulnerability
var v2KevCmd = &cobra.Command{
	Use:   "kev <vuln-id>",
	Short: "Get CISA KEV status for a vulnerability (V2)",
	Long: `Retrieve CISA Known Exploited Vulnerabilities (KEV) data from the V2 API.

Requires -V v2.

Examples:
  vulnetix vdb kev CVE-2021-44228 -V v2
  vulnetix vdb kev CVE-2021-44228 -V v2 --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireV2("kev"); err != nil {
			return err
		}

		client := newVDBClient()
		vdbLog(cmd).Infof("🛡️ Fetching KEV status for %s...", args[0])

		result, err := client.V2Kev(args[0])
		if err != nil {
			return fmt.Errorf("failed to get KEV data: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("kev", args[0])
		return vdbRender(cmd, result, display.RenderKev)
	},
}

// v2TimelineCmd retrieves timeline data for a vulnerability
var v2TimelineCmd = &cobra.Command{
	Use:   "timeline <vuln-id>",
	Short: "Get vulnerability timeline (V2)",
	Long: `Retrieve the vulnerability timeline from the V2 API.

Requires -V v2. Returns events[], sources{} (source transparency), and meta{}.

Event types: source, exploit, score-change, patch, advisory, scorecard

Examples:
  vulnetix vdb timeline CVE-2021-44228 -V v2
  vulnetix vdb timeline CVE-2021-44228 -V v2 --include exploit
  vulnetix vdb timeline CVE-2021-44228 -V v2 --exclude score-change --scores-limit 10
  vulnetix vdb timeline CVE-2021-44228 -V v2 --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireV2("timeline"); err != nil {
			return err
		}

		include, _ := cmd.Flags().GetString("include")
		exclude, _ := cmd.Flags().GetString("exclude")
		dates, _ := cmd.Flags().GetString("dates")
		scoresLimit, _ := cmd.Flags().GetInt("scores-limit")

		client := newVDBClient()
		vdbLog(cmd).Infof("📅 Fetching timeline for %s...", args[0])

		result, err := client.V2Timeline(args[0], vdb.V2TimelineParams{
			Include:     include,
			Exclude:     exclude,
			Dates:       dates,
			ScoresLimit: scoresLimit,
		})
		if err != nil {
			return fmt.Errorf("failed to get timeline: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("timeline", args[0])
		return vdbRender(cmd, result, display.RenderTimeline)
	},
}

// v2AffectedCmd retrieves affected product/package data
var v2AffectedCmd = &cobra.Command{
	Use:   "affected <vuln-id>",
	Short: "Get affected products/packages for a vulnerability (V2)",
	Long: `Retrieve affected product and package data from the V2 API.

Requires -V v2.

Examples:
  vulnetix vdb affected CVE-2021-44228 -V v2
  vulnetix vdb affected CVE-2021-44228 -V v2 --ecosystem npm
  vulnetix vdb affected CVE-2021-44228 -V v2 --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireV2("affected"); err != nil {
			return err
		}

		client := newVDBClient()
		p := buildV2QueryParams(cmd)

		vdbLog(cmd).Infof("🎯 Fetching affected data for %s...", args[0])

		result, err := client.V2Affected(args[0], p)
		if err != nil {
			return fmt.Errorf("failed to get affected data: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("affected", args[0])
		return vdbRender(cmd, result, display.RenderAffected)
	},
}

// v2ScorecardCmd retrieves the vulnerability scorecard
var v2ScorecardCmd = &cobra.Command{
	Use:   "scorecard <vuln-id>",
	Short: "Get vulnerability scorecard (V2)",
	Long: `Retrieve the vulnerability scorecard from the V2 API.

Requires -V v2.

Examples:
  vulnetix vdb scorecard CVE-2021-44228 -V v2
  vulnetix vdb scorecard CVE-2021-44228 -V v2 --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireV2("scorecard"); err != nil {
			return err
		}

		client := newVDBClient()
		vdbLog(cmd).Infof("📊 Fetching scorecard for %s...", args[0])

		result, err := client.V2Scorecard(args[0])
		if err != nil {
			return fmt.Errorf("failed to get scorecard: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("scorecard", args[0])
		return vdbRender(cmd, result, display.RenderScorecard)
	},
}

// v2ScorecardSearchCmd searches scorecards by repository name
var v2ScorecardSearchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search scorecards by repository name (V2)",
	Long: `Search OpenSSF Scorecards by repository name.

Requires -V v2.

Examples:
  vulnetix vdb scorecard search openssl -V v2
  vulnetix vdb scorecard search github.com/openssl/openssl -V v2 --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireV2("scorecard search"); err != nil {
			return err
		}

		client := newVDBClient()
		vdbLog(cmd).Infof("🔍 Searching scorecards for %q...", args[0])

		result, err := client.V2ScorecardSearch(args[0])
		if err != nil {
			return fmt.Errorf("failed to search scorecards: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("scorecard search", args[0])
		return vdbRender(cmd, result, display.RenderScorecardSearch)
	},
}

// v2RemediationCmd is the parent for remediation subcommands
var v2RemediationCmd = &cobra.Command{
	Use:   "remediation",
	Short: "Remediation intelligence (V2)",
}

// v2RemediationPlanCmd retrieves a context-aware remediation plan
var v2RemediationPlanCmd = &cobra.Command{
	Use:   "plan <vuln-id>",
	Short: "Get a context-aware remediation plan (V2)",
	Long: `Retrieve a context-aware remediation plan for a vulnerability from the V2 API.
The plan includes prioritized actions, severity assessment, SSVC decision,
fix availability, and optionally CWE guidance and verification steps.

Requires -V v2.

Examples:
  vulnetix vdb remediation plan CVE-2021-44228 -V v2
  vulnetix vdb remediation plan CVE-2021-44228 -V v2 --include-guidance
  vulnetix vdb remediation plan CVE-2021-44228 -V v2 --ecosystem npm --package-name log4j
  vulnetix vdb remediation plan CVE-2021-44228 -V v2 --purl "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
  vulnetix vdb remediation plan CVE-2021-44228 -V v2 --include-guidance --include-verification-steps --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireV2("remediation plan"); err != nil {
			return err
		}

		client := newVDBClient()

		p := vdb.V2RemediationParams{}
		p.Ecosystem, _ = cmd.Flags().GetString("ecosystem")
		p.PackageName, _ = cmd.Flags().GetString("package-name")
		p.Vendor, _ = cmd.Flags().GetString("vendor")
		p.Product, _ = cmd.Flags().GetString("product")
		p.Purl, _ = cmd.Flags().GetString("purl")
		p.CurrentVersion, _ = cmd.Flags().GetString("current-version")
		p.PackageManager, _ = cmd.Flags().GetString("package-manager")
		p.ContainerImage, _ = cmd.Flags().GetString("container-image")
		p.OS, _ = cmd.Flags().GetString("os")
		p.Registry, _ = cmd.Flags().GetString("registry")
		p.IncludeGuidance, _ = cmd.Flags().GetBool("include-guidance")
		p.IncludeVerificationSteps, _ = cmd.Flags().GetBool("include-verification-steps")

		vdbLog(cmd).Infof("📋 Fetching remediation plan for %s...", args[0])

		result, err := client.V2RemediationPlan(args[0], p)
		if err != nil {
			return fmt.Errorf("failed to get remediation plan: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("remediation plan", args[0])
		return vdbRender(cmd, result, display.RenderRemediationPlan)
	},
}

// v2CloudLocatorsCmd retrieves cloud resource locator templates
var v2CloudLocatorsCmd = &cobra.Command{
	Use:   "cloud-locators",
	Short: "Get cloud resource locator templates for a vendor/product (V2)",
	Long: `Derive cloud-native resource identifier templates (AWS ARN, Azure Resource ID,
GCP Resource Name, Cloudflare Locator, Oracle OCID) from vendor/product pairs.

Templates contain placeholders for account-specific values that you fill in
to match your infrastructure resources.

Requires -V v2.

Examples:
  vulnetix vdb cloud-locators --vendor amazon --product s3 -V v2
  vulnetix vdb cloud-locators --vendor microsoft --product storage -V v2
  vulnetix vdb cloud-locators --vendor google --product compute -V v2
  vulnetix vdb cloud-locators --vendor cloudflare --product workers -V v2
  vulnetix vdb cloud-locators --vendor oracle --product compute -V v2
  vulnetix vdb cloud-locators --vendor amazon --product cloudfront -V v2 --output json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireV2("cloud-locators"); err != nil {
			return err
		}

		vendor, _ := cmd.Flags().GetString("vendor")
		product, _ := cmd.Flags().GetString("product")

		if vendor == "" && product == "" {
			return fmt.Errorf("at least one of --vendor or --product is required")
		}

		client := newVDBClient()
		vdbLog(cmd).Infof("Fetching cloud locators for vendor=%s product=%s...", vendor, product)

		result, err := client.V2CloudLocators(vendor, product)
		if err != nil {
			return fmt.Errorf("failed to get cloud locators: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("cloud-locators", vendor+"/"+product)
		return vdbRender(cmd, result, display.RenderCloudLocators)
	},
}

// v2FixesMerged handles the -V v2 case for the fixes command by calling
// all three V2 fix endpoints in parallel and merging the results.
func v2FixesMerged(identifier string, cmd *cobra.Command) (map[string]interface{}, error) {
	client := newVDBClient()
	p := buildV2QueryParams(cmd)

	type result struct {
		key  string
		data map[string]interface{}
		err  error
	}

	ch := make(chan result, 3)
	var wg sync.WaitGroup

	wg.Add(3)
	go func() {
		defer wg.Done()
		data, err := client.V2RegistryFixes(identifier, p)
		ch <- result{"registry", data, err}
	}()
	go func() {
		defer wg.Done()
		data, err := client.V2DistributionPatches(identifier, p)
		ch <- result{"distributions", data, err}
	}()
	go func() {
		defer wg.Done()
		data, err := client.V2SourceFixes(identifier, p)
		ch <- result{"source", data, err}
	}()

	go func() {
		wg.Wait()
		close(ch)
	}()

	merged := map[string]interface{}{
		"identifier": identifier,
	}
	for r := range ch {
		if r.err != nil {
			merged[r.key] = map[string]interface{}{"error": r.err.Error()}
		} else {
			merged[r.key] = r.data
		}
	}

	printRateLimit(client)
	return merged, nil
}

func init() {
	// V2-only commands
	vdbCmd.AddCommand(v2WorkaroundsCmd)
	vdbCmd.AddCommand(v2AdvisoriesCmd)
	vdbCmd.AddCommand(v2CweCmd)
	vdbCmd.AddCommand(v2KevCmd)
	vdbCmd.AddCommand(v2TimelineCmd)
	vdbCmd.AddCommand(v2AffectedCmd)
	vdbCmd.AddCommand(v2ScorecardCmd)
	vdbCmd.AddCommand(v2RemediationCmd)
	vdbCmd.AddCommand(v2CloudLocatorsCmd)

	// Cloud locators flags
	v2CloudLocatorsCmd.Flags().String("vendor", "", "Vendor name (e.g. amazon, microsoft, google)")
	v2CloudLocatorsCmd.Flags().String("product", "", "Product/service name (e.g. s3, ec2, cloudfront)")

	// Scorecard subcommands
	v2ScorecardCmd.AddCommand(v2ScorecardSearchCmd)

	// CWE subcommands
	v2CweCmd.AddCommand(v2CweGuidanceCmd)

	// Remediation subcommands
	v2RemediationCmd.AddCommand(v2RemediationPlanCmd)

	// Timeline flags
	v2TimelineCmd.Flags().String("include", "", "Comma-separated event types to include (source,exploit,score-change,patch,advisory,scorecard)")
	v2TimelineCmd.Flags().String("exclude", "", "Comma-separated event types to exclude")
	v2TimelineCmd.Flags().String("dates", "", "CVE date fields: published,modified,reserved (default: all)")
	v2TimelineCmd.Flags().Int("scores-limit", 30, "Max score-change events (max 365)")
	_ = v2TimelineCmd.RegisterFlagCompletionFunc("dates", cobra.FixedCompletions([]string{"published", "modified", "reserved"}, cobra.ShellCompDirectiveNoFileComp))

	// Affected flags
	addV2ContextFlags(v2AffectedCmd)
	addV2PaginationFlags(v2AffectedCmd)

	// Remediation plan flags (most flags of any command)
	v2RemediationPlanCmd.Flags().String("ecosystem", "", "Filter by package ecosystem")
	v2RemediationPlanCmd.Flags().String("package-name", "", "Filter by package name")
	v2RemediationPlanCmd.Flags().String("vendor", "", "Filter by vendor name")
	v2RemediationPlanCmd.Flags().String("product", "", "Filter by product name")
	v2RemediationPlanCmd.Flags().String("purl", "", "Package URL (overrides ecosystem + package-name)")
	v2RemediationPlanCmd.Flags().String("current-version", "", "Current package version")
	v2RemediationPlanCmd.Flags().String("package-manager", "", "Package manager (npm, pip, cargo, etc.)")
	v2RemediationPlanCmd.Flags().String("container-image", "", "Container image reference")
	v2RemediationPlanCmd.Flags().String("os", "", "OS identifier (e.g. ubuntu:22.04)")
	v2RemediationPlanCmd.Flags().String("registry", "", "Registry URL")
	v2RemediationPlanCmd.Flags().Bool("include-guidance", false, "Include CWE-based guidance text")
	v2RemediationPlanCmd.Flags().Bool("include-verification-steps", false, "Include verification steps in actions")
}
