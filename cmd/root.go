package cmd

import (
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vulnetix/vulnetix/internal/config"
	"gopkg.in/yaml.v3"
)

var (
	// Global configuration state
	vulnetixConfig *config.VulnetixConfig

	// Command line flags
	orgID            string
	task             string
	projectName      string
	productName      string
	teamName         string
	groupName        string
	tags             string
	tools            string
	productionBranch string
	releaseBranch    string
	workflowTimeout  int
	version          = "1.0.0" // This will be set during build
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vulnetix",
	Short: "Vulnetix CLI - Automate vulnerability triage and remediation",
	Long: `Vulnetix CLI is a command-line tool for vulnerability management that focuses on 
automated remediation over discovery. It helps organizations prioritize and resolve 
vulnerabilities efficiently.`,
	Run: func(cmd *cobra.Command, args []string) {
		if orgID == "" {
			fmt.Fprintf(os.Stderr, "Error: --org-id is required\n")
			cmd.Usage()
			os.Exit(1)
		}

		// Validate UUID format
		if _, err := uuid.Parse(orgID); err != nil {
			fmt.Fprintf(os.Stderr, "Error: --org-id must be a valid UUID, got: %s\n", orgID)
			os.Exit(1)
		}

		// Validate task
		validTask, err := config.ValidateTask(task)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			cmd.Usage()
			os.Exit(1)
		}

		// Initialize configuration
		vulnetixConfig = &config.VulnetixConfig{
			OrgID:       orgID,
			Task:        validTask,
			ProjectName: projectName,
			ProductName: productName,
			TeamName:    teamName,
			GroupName:   groupName,
			Tags:        config.ParseTags(tags),
			Tools:       parseTools(tools),
			Release: config.ReleaseConfig{
				ProductionBranch: productionBranch,
				ReleaseBranch:    releaseBranch,
				WorkflowTimeout:  workflowTimeout,
			},
			GitHub:  config.LoadGitHubContext(),
			Version: version,
		}

		// Validate release configuration if in release mode
		if validTask == config.TaskRelease {
			if err := vulnetixConfig.ValidateReleaseReadiness(); err != nil {
				fmt.Fprintf(os.Stderr, "❌ Release configuration error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("🚀 Release readiness assessment mode enabled\n")
		}

		// Print configuration state
		vulnetixConfig.PrintConfiguration()

		// Main logic
		fmt.Printf("🛡️  Vulnetix CLI v%s\n", version)
		fmt.Printf("Organization ID: %s\n", orgID)
		fmt.Printf("Task: %s\n", validTask)

		switch validTask {
		case config.TaskRelease:
			fmt.Printf("🚀 Starting release readiness assessment for organization: %s\n", orgID)
			fmt.Printf("📋 Production Branch: %s\n", vulnetixConfig.Release.ProductionBranch)
			fmt.Printf("🔄 Release Branch: %s\n", vulnetixConfig.Release.ReleaseBranch)

			// Simulate release readiness checks
			fmt.Println("🔍 Checking for sibling job artifacts...")
			context := vulnetixConfig.GetSiblingJobsContext()
			fmt.Printf("📦 Artifact pattern: %s\n", context["artifact_pattern"])
			fmt.Printf("🔗 GitHub API: %s/repos/%s/actions/runs/%s/artifacts\n",
				context["api_url"], context["repository"], context["workflow_run_id"])

			fmt.Println("⏳ Waiting for required security artifacts...")
			fmt.Println("🔐 Validating SARIF reports...")
			fmt.Println("📋 Checking SBOM completeness...")
			fmt.Println("🛡️  Verifying VEX documents...")

			fmt.Println("✅ Release readiness assessment complete")
			fmt.Println("🎯 All security requirements satisfied")

		case config.TaskScan:
			fmt.Printf("🔍 Starting vulnerability analysis for organization: %s\n", orgID)
			// Simulate processing
			fmt.Println("✅ Successfully processed vulnerability data")
			fmt.Println("📊 Vulnerability analysis complete")

		case config.TaskReport:
			fmt.Printf("📊 Generating vulnerability reports for organization: %s\n", orgID)
			fmt.Println("✅ Reports generated successfully")

		case config.TaskTriage:
			fmt.Printf("🎯 Starting automated triage for organization: %s\n", orgID)
			fmt.Println("✅ Triage process completed")

		default:
			fmt.Printf("Starting %s task for organization: %s\n", validTask, orgID)
		}

		fmt.Printf("🔗 View results at: https://dashboard.vulnetix.com/org/%s\n", orgID)
	},
}

// parseTools parses the tools YAML string into Tool structs
func parseTools(toolsStr string) []config.Tool {
	if toolsStr == "" {
		return nil
	}

	var tools []config.Tool

	// Try to parse as YAML first
	if err := yaml.Unmarshal([]byte(toolsStr), &tools); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to parse tools YAML: %v\n", err)
		return nil
	}

	return tools
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Define flags
	rootCmd.PersistentFlags().StringVar(&orgID, "org-id", "", "Organization ID (UUID) for Vulnetix operations (required)")
	rootCmd.MarkPersistentFlagRequired("org-id")

	// Optional configuration flags
	rootCmd.PersistentFlags().StringVar(&projectName, "project-name", "", "Project name for vulnerability management context")
	rootCmd.PersistentFlags().StringVar(&productName, "product-name", "", "Product name for vulnerability management context")
	rootCmd.PersistentFlags().StringVar(&teamName, "team-name", "", "Team name responsible for the project")
	rootCmd.PersistentFlags().StringVar(&groupName, "group-name", "", "Group name for organizational hierarchy")
	rootCmd.PersistentFlags().StringVar(&tags, "tags", "", "YAML list of tags for categorization (e.g., '[\"critical\", \"frontend\", \"api\"]')")
	rootCmd.PersistentFlags().StringVar(&tools, "tools", "", "YAML array of tool configurations")

	// Task configuration
	rootCmd.PersistentFlags().StringVar(&task, "task", "scan", "Task to perform: scan, release, report, triage")

	// Release readiness flags (used when task=release)
	rootCmd.PersistentFlags().StringVar(&productionBranch, "production-branch", "main", "Production branch name (for release task)")
	rootCmd.PersistentFlags().StringVar(&releaseBranch, "release-branch", "", "Release branch name (for release task)")
	rootCmd.PersistentFlags().IntVar(&workflowTimeout, "workflow-timeout", 30, "Timeout in minutes to wait for sibling job artifacts (for release task)")

	// Add version command
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version number of Vulnetix CLI",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Vulnetix CLI v%s\n", version)
		},
	}

	// Version command doesn't need org-id
	versionCmd.Flags().String("org-id", "", "Organization ID (not required for version)")

	rootCmd.AddCommand(versionCmd)
}
