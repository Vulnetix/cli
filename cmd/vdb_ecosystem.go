package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// ecosystemCmd is the parent for ecosystem-scoped subcommands
var ecosystemCmd = &cobra.Command{
	Use:   "ecosystem",
	Short: "Ecosystem-scoped package and group lookups",
	Long: `Query packages and groups within a specific ecosystem.

Examples:
  vulnetix vdb ecosystem package npm express
  vulnetix vdb ecosystem package npm express --versions
  vulnetix vdb ecosystem group maven org.apache.commons commons-lang3`,
}

// ecosystemPackageCmd retrieves package info scoped to an ecosystem
var ecosystemPackageCmd = &cobra.Command{
	Use:   "package <ecosystem> <package-name>",
	Short: "Get package information within an ecosystem",
	Long: `Retrieve package information scoped to a specific ecosystem.
Use --versions to retrieve version information instead.

Examples:
  vulnetix vdb ecosystem package npm express
  vulnetix vdb ecosystem package npm express --versions
  vulnetix vdb ecosystem package pypi requests --output json`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ecosystem := args[0]
		pkg := args[1]
		showVersions, _ := cmd.Flags().GetBool("versions")

		client := newVDBClient()

		if showVersions {
			if vdbOutput == "json" {
				fmt.Fprintf(os.Stderr, "📦 Fetching versions for %s/%s...\n", ecosystem, pkg)
			} else {
				fmt.Printf("📦 Fetching versions for %s/%s...\n", ecosystem, pkg)
			}

			result, err := client.GetEcosystemPackageVersions(ecosystem, pkg)
			if err != nil {
				return fmt.Errorf("failed to get ecosystem package versions: %w", err)
			}
			printRateLimit(client)
			return printOutput(result, vdbOutput)
		}

		if vdbOutput == "json" {
			fmt.Fprintf(os.Stderr, "📦 Fetching package info for %s/%s...\n", ecosystem, pkg)
		} else {
			fmt.Printf("📦 Fetching package info for %s/%s...\n", ecosystem, pkg)
		}

		result, err := client.GetEcosystemPackage(ecosystem, pkg)
		if err != nil {
			return fmt.Errorf("failed to get ecosystem package: %w", err)
		}
		printRateLimit(client)
		return printOutput(result, vdbOutput)
	},
}

// ecosystemGroupCmd retrieves Maven-style group/artifact info
var ecosystemGroupCmd = &cobra.Command{
	Use:   "group <ecosystem> <group> <artifact>",
	Short: "Get group/artifact information (Maven-style coordinates)",
	Long: `Retrieve package information using Maven-style group/artifact coordinates
within a specific ecosystem.

Examples:
  vulnetix vdb ecosystem group maven org.apache.commons commons-lang3
  vulnetix vdb ecosystem group maven com.google.guava guava --output json`,
	Args: cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		ecosystem := args[0]
		group := args[1]
		artifact := args[2]

		client := newVDBClient()

		if vdbOutput == "json" {
			fmt.Fprintf(os.Stderr, "📦 Fetching %s/%s/%s...\n", ecosystem, group, artifact)
		} else {
			fmt.Printf("📦 Fetching %s/%s/%s...\n", ecosystem, group, artifact)
		}

		result, err := client.GetEcosystemGroupPackage(ecosystem, group, artifact)
		if err != nil {
			return fmt.Errorf("failed to get ecosystem group package: %w", err)
		}
		printRateLimit(client)
		return printOutput(result, vdbOutput)
	},
}

func init() {
	// Add ecosystem parent to vdb
	vdbCmd.AddCommand(ecosystemCmd)

	// Add subcommands
	ecosystemCmd.AddCommand(ecosystemPackageCmd)
	ecosystemCmd.AddCommand(ecosystemGroupCmd)

	// Flags
	ecosystemPackageCmd.Flags().Bool("versions", false, "Show version information instead of package info")
}
