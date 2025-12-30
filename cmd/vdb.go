package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vulnetix/vulnetix/internal/vdb"
)

var (
	vdbOrgID     string
	vdbSecretKey string
	vdbBaseURL   string
	vdbLimit     int
	vdbOffset    int
	vdbOutput    string
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
  # Get information about a CVE
  vulnetix vdb cve CVE-2024-1234

  # List available ecosystems
  vulnetix vdb ecosystems

  # Get versions for a product
  vulnetix vdb product express

  # Get vulnerabilities for a package
  vulnetix vdb vulns express`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Load credentials if not provided via flags
		if vdbOrgID == "" || vdbSecretKey == "" {
			orgID, secret, err := vdb.LoadCredentials()
			if err != nil {
				return err
			}
			if vdbOrgID == "" {
				vdbOrgID = orgID
			}
			if vdbSecretKey == "" {
				vdbSecretKey = secret
			}
		}
		return nil
	},
}

// cveCmd retrieves information about a specific CVE
var cveCmd = &cobra.Command{
	Use:   "cve <CVE-ID>",
	Short: "Get information about a specific CVE",
	Long: `Retrieve detailed vulnerability information for a specific CVE identifier.

Examples:
  vulnetix vdb cve CVE-2024-1234
  vulnetix vdb cve CVE-2024-1234 --output json
  vulnetix vdb cve CVE-2024-1234 -o pretty`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cveID := args[0]

		client := vdb.NewClient(vdbOrgID, vdbSecretKey)
		if vdbBaseURL != "" {
			client.BaseURL = vdbBaseURL
		}

		fmt.Printf("🔍 Fetching information for %s...\n", cveID)

		cveInfo, err := client.GetCVE(cveID)
		if err != nil {
			return fmt.Errorf("failed to get CVE: %w", err)
		}

		return printOutput(cveInfo.Data, vdbOutput)
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
		client := vdb.NewClient(vdbOrgID, vdbSecretKey)
		if vdbBaseURL != "" {
			client.BaseURL = vdbBaseURL
		}

		fmt.Println("🌐 Fetching available ecosystems...")

		ecosystems, err := client.GetEcosystems()
		if err != nil {
			return fmt.Errorf("failed to get ecosystems: %w", err)
		}

		if vdbOutput == "json" {
			return printOutput(map[string]interface{}{"ecosystems": ecosystems}, vdbOutput)
		}

		fmt.Printf("\n✅ Found %d ecosystems:\n\n", len(ecosystems))
		for _, eco := range ecosystems {
			fmt.Printf("  • %s\n", eco)
		}

		return nil
	},
}

// productCmd retrieves product version information
var productCmd = &cobra.Command{
	Use:   "product <product-name> [version]",
	Short: "Get product version information",
	Long: `Retrieve version information for a specific product.

If no version is specified, lists all available versions.
If a version is specified, retrieves detailed information for that version.

Examples:
  # List all versions
  vulnetix vdb product express

  # Get specific version
  vulnetix vdb product express 4.17.1

  # With pagination
  vulnetix vdb product express --limit 50 --offset 100`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		productName := args[0]

		client := vdb.NewClient(vdbOrgID, vdbSecretKey)
		if vdbBaseURL != "" {
			client.BaseURL = vdbBaseURL
		}

		// If version is provided, get specific version info
		if len(args) > 1 {
			version := args[1]
			fmt.Printf("🔍 Fetching information for %s@%s...\n", productName, version)

			info, err := client.GetProductVersion(productName, version)
			if err != nil {
				return fmt.Errorf("failed to get product version: %w", err)
			}

			return printOutput(info, vdbOutput)
		}

		// Otherwise, list all versions
		fmt.Printf("📦 Fetching versions for %s...\n", productName)

		resp, err := client.GetProductVersions(productName, vdbLimit, vdbOffset)
		if err != nil {
			return fmt.Errorf("failed to get product versions: %w", err)
		}

		if vdbOutput == "json" {
			return printOutput(resp, vdbOutput)
		}

		fmt.Printf("\n✅ Found %d total versions (showing %d):\n\n", resp.Total, len(resp.Versions))
		for i, version := range resp.Versions {
			fmt.Printf("  %d. %s\n", i+1, version)
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

		client := vdb.NewClient(vdbOrgID, vdbSecretKey)
		if vdbBaseURL != "" {
			client.BaseURL = vdbBaseURL
		}

		fmt.Printf("🔒 Fetching vulnerabilities for %s...\n", packageName)

		resp, err := client.GetPackageVulnerabilities(packageName, vdbLimit, vdbOffset)
		if err != nil {
			return fmt.Errorf("failed to get vulnerabilities: %w", err)
		}

		if vdbOutput == "json" {
			return printOutput(resp, vdbOutput)
		}

		fmt.Printf("\n⚠️  Found %d total vulnerabilities (showing %d):\n\n", resp.Total, len(resp.Vulnerabilities))
		for i, vuln := range resp.Vulnerabilities {
			cveID := "Unknown"
			if id, ok := vuln["cve"].(string); ok {
				cveID = id
			} else if id, ok := vuln["id"].(string); ok {
				cveID = id
			}

			fmt.Printf("  %d. %s\n", i+1, cveID)

			// Print severity if available
			if severity, ok := vuln["severity"].(string); ok {
				fmt.Printf("     Severity: %s\n", severity)
			}
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
		client := vdb.NewClient(vdbOrgID, vdbSecretKey)
		if vdbBaseURL != "" {
			client.BaseURL = vdbBaseURL
		}

		fmt.Println("📋 Fetching OpenAPI specification...")

		spec, err := client.GetOpenAPISpec()
		if err != nil {
			return fmt.Errorf("failed to get spec: %w", err)
		}

		return printOutput(spec, vdbOutput)
	},
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
	vdbCmd.AddCommand(cveCmd)
	vdbCmd.AddCommand(ecosystemsCmd)
	vdbCmd.AddCommand(productCmd)
	vdbCmd.AddCommand(vulnsCmd)
	vdbCmd.AddCommand(specCmd)

	// Global flags
	vdbCmd.PersistentFlags().StringVar(&vdbOrgID, "org-id", "", "Organization UUID (overrides VVD_ORG env var)")
	vdbCmd.PersistentFlags().StringVar(&vdbSecretKey, "secret", "", "Secret key (overrides VVD_SECRET env var)")
	vdbCmd.PersistentFlags().StringVar(&vdbBaseURL, "base-url", vdb.DefaultBaseURL, "VDB API base URL")
	vdbCmd.PersistentFlags().StringVarP(&vdbOutput, "output", "o", "pretty", "Output format (json, pretty)")

	// Pagination flags for applicable commands
	productCmd.Flags().IntVar(&vdbLimit, "limit", 100, "Maximum number of results to return")
	productCmd.Flags().IntVar(&vdbOffset, "offset", 0, "Number of results to skip")

	vulnsCmd.Flags().IntVar(&vdbLimit, "limit", 100, "Maximum number of results to return")
	vulnsCmd.Flags().IntVar(&vdbOffset, "offset", 0, "Number of results to skip")
}
