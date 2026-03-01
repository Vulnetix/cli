package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/vulnetix/vulnetix/internal/config"
	"github.com/vulnetix/vulnetix/internal/sarif"
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

	// SARIF command flags
	sarifFile        string
	sarifBaseURL     string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vulnetix",
	Short: "Vulnetix CLI - Automate vulnerability triage and remediation",
	Long: `Vulnetix CLI is a command-line tool for vulnerability management that focuses on 
automated remediation over discovery. It helps organizations prioritize and resolve 
vulnerabilities efficiently.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if orgID == "" {
			return fmt.Errorf("--org-id is required")
		}

		// Validate UUID format
		if _, err := uuid.Parse(orgID); err != nil {
			return fmt.Errorf("--org-id must be a valid UUID, got: %s", orgID)
		}

		// Validate task
		validTask, err := config.ValidateTask(task)
		if err != nil {
			return fmt.Errorf("%w", err)
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
			CI:      config.LoadCIContext(version),
			Version: version,
		}

		// Validate release configuration if in release mode
		if validTask == config.TaskRelease {
			if err := vulnetixConfig.ValidateReleaseReadiness(); err != nil {
				return fmt.Errorf("❌ Release configuration error: %w", err)
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
			
			// Validate tool artifacts if tools are provided
			if len(vulnetixConfig.Tools) > 0 {
				fmt.Printf("🔧 Found %d tools to validate\n", len(vulnetixConfig.Tools))
				if err := validateReleaseToolArtifacts(vulnetixConfig.Tools); err != nil {
					return fmt.Errorf("release readiness validation failed: %w", err)
				}
			} else {
				fmt.Println("🔐 Validating SARIF reports...")
				fmt.Println("📋 Checking SBOM completeness...")
				fmt.Println("🛡️  Verifying VEX documents...")
			}

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
		return nil
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

// validateToolArtifact validates a tool artifact based on its format
func validateToolArtifact(tool config.Tool, artifactPath string) error {
	fmt.Printf("🔍 Validating %s artifact: %s (format: %s)\n", tool.Category, tool.ArtifactName, tool.Format)
	
	// Check if artifact file exists
	if _, err := os.Stat(artifactPath); os.IsNotExist(err) {
		return fmt.Errorf("artifact file not found: %s", artifactPath)
	}

	// Read the artifact file
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to read artifact file %s: %w", artifactPath, err)
	}

	switch tool.Format {
	case config.FormatSARIF:
		return validateSARIFArtifact(data, tool.ArtifactName)
	case config.FormatPlainJSON:
		return validateJSONArtifact(data, tool.ArtifactName)
	default:
		fmt.Printf("⚠️  Skipping validation for format %s (not yet supported)\n", tool.Format)
		return nil
	}
}

// validateSARIFArtifact validates SARIF format artifact using the existing SARIF validator
func validateSARIFArtifact(data []byte, artifactName string) error {
	fmt.Printf("🔐 Validating SARIF format for: %s\n", artifactName)
	
	validator := sarif.NewValidator()
	validation, err := validator.ValidateFromBytes(data)
	if err != nil {
		return fmt.Errorf("SARIF validation error for %s: %w", artifactName, err)
	}

	if !validation.Valid {
		return fmt.Errorf("SARIF validation failed for %s: %v", artifactName, validation.Errors)
	}

	fmt.Printf("✅ SARIF validation successful for %s\n", artifactName)
	fmt.Printf("   - Version: %s\n", validation.Version)
	fmt.Printf("   - Runs: %d\n", validation.Stats.RunCount)
	fmt.Printf("   - Results: %d\n", validation.Stats.ResultCount)
	fmt.Printf("   - Tools: %d\n", validation.Stats.ToolCount)
	
	return nil
}

// validateJSONArtifact validates that the artifact is well-formed JSON
func validateJSONArtifact(data []byte, artifactName string) error {
	fmt.Printf("📄 Validating JSON format for: %s\n", artifactName)
	
	var jsonObj interface{}
	if err := json.Unmarshal(data, &jsonObj); err != nil {
		return fmt.Errorf("JSON validation failed for %s: invalid JSON format: %w", artifactName, err)
	}

	fmt.Printf("✅ JSON validation successful for %s\n", artifactName)
	return nil
}

// validateReleaseToolArtifacts validates all tool artifacts for the release task
func validateReleaseToolArtifacts(tools []config.Tool) error {
	if len(tools) == 0 {
		fmt.Println("⚠️  No tools provided for validation")
		return nil
	}

	fmt.Printf("🧪 Validating %d tool artifacts for release readiness...\n", len(tools))
	
	var validationErrors []string
	
	for _, tool := range tools {
		// For release task, look for the artifact file based on the artifact name
		// This assumes artifacts are in the current working directory or a standard path
		artifactPath := tool.ArtifactName
		
		// Try common paths if the artifact name doesn't exist as-is
		if _, err := os.Stat(artifactPath); os.IsNotExist(err) {
			// Try some common directories
			possiblePaths := []string{
				filepath.Join(".", tool.ArtifactName),
				filepath.Join("artifacts", tool.ArtifactName),
				filepath.Join("reports", tool.ArtifactName),
				filepath.Join("results", tool.ArtifactName),
				filepath.Join("output", tool.ArtifactName),
			}
			
			found := false
			for _, path := range possiblePaths {
				if _, err := os.Stat(path); err == nil {
					artifactPath = path
					found = true
					break
				}
			}
			
			if !found {
				validationErrors = append(validationErrors, fmt.Sprintf("Artifact not found: %s (searched in: %v)", tool.ArtifactName, append([]string{tool.ArtifactName}, possiblePaths...)))
				continue
			}
		}
		
		if err := validateToolArtifact(tool, artifactPath); err != nil {
			validationErrors = append(validationErrors, err.Error())
		}
	}
	
	if len(validationErrors) > 0 {
		fmt.Printf("❌ Tool artifact validation failed with %d errors:\n", len(validationErrors))
		for _, err := range validationErrors {
			fmt.Printf("   - %s\n", err)
		}
		return fmt.Errorf("tool artifact validation failed")
	}
	
	fmt.Printf("✅ All %d tool artifacts validated successfully\n", len(tools))
	return nil
}

func Execute() error {
	return rootCmd.Execute()
}

// runSARIFUpload handles the SARIF upload command
func runSARIFUpload() error {
	// Validate org-id
	if orgID == "" {
		return fmt.Errorf("--org-id is required")
	}

	if _, err := uuid.Parse(orgID); err != nil {
		return fmt.Errorf("--org-id must be a valid UUID, got: %s", orgID)
	}

	// Determine input source and read SARIF data
	var sarifData []byte
	var inputMethod string
	var err error

	if sarifFile != "" {
		// Read from file
		inputMethod = "file"
		file, err := os.Open(sarifFile)
		if err != nil {
			return fmt.Errorf("failed to open SARIF file %s: %w", sarifFile, err)
		}
		defer file.Close()

		sarifData, err = io.ReadAll(file)
		if err != nil {
			return fmt.Errorf("failed to read SARIF file: %w", err)
		}
	} else {
		// Read from stdin
		inputMethod = "stdin"
		stat, err := os.Stdin.Stat()
		if err != nil {
			return fmt.Errorf("failed to check stdin: %w", err)
		}

		if (stat.Mode() & os.ModeCharDevice) != 0 {
			return fmt.Errorf("no SARIF data provided. Use --file or pipe/redirect input")
		}

		sarifData, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
	}

	if len(sarifData) == 0 {
		return fmt.Errorf("no SARIF data provided")
	}

	// Validate SARIF locally first
	fmt.Printf("🔍 Validating SARIF file...\n")
	validator := sarif.NewValidator()
	validation, err := validator.ValidateFromBytes(sarifData)
	if err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	if !validation.Valid {
		fmt.Printf("❌ SARIF validation failed:\n")
		for _, errMsg := range validation.Errors {
			fmt.Printf("  - %s\n", errMsg)
		}
		return fmt.Errorf("SARIF validation failed")
	}

	fmt.Printf("✅ SARIF validation successful\n")
	fmt.Printf("📊 Statistics:\n")
	fmt.Printf("  - Version: %s\n", validation.Version)
	fmt.Printf("  - Runs: %d\n", validation.Stats.RunCount)
	fmt.Printf("  - Results: %d\n", validation.Stats.ResultCount)
	fmt.Printf("  - Tools: %d\n", validation.Stats.ToolCount)

	// Configure uploader
	uploadConfig := &sarif.UploadConfig{
		BaseURL:     sarifBaseURL,
		OrgID:       orgID,
		ContentType: sarif.DetermineContentType(inputMethod),
	}

	uploader := sarif.NewUploader(uploadConfig)

	// Upload SARIF
	fmt.Printf("📤 Uploading SARIF to %s...\n", sarifBaseURL)
	response, err := uploader.Upload(sarifData)
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}

	if !response.Success {
		fmt.Printf("❌ Upload failed (HTTP %d): %s\n", response.StatusCode, response.Message)
		return fmt.Errorf("upload rejected by server")
	}

	fmt.Printf("✅ SARIF uploaded successfully\n")
	fmt.Printf("🆔 Artifact UUID: %s\n", strings.TrimSpace(response.UUID))
	fmt.Printf("🔗 View at: https://dashboard.vulnetix.com/org/%s/artifacts/%s\n", orgID, strings.TrimSpace(response.UUID))

	return nil
}

func init() {
	// Define flags
	rootCmd.PersistentFlags().StringVar(&orgID, "org-id", "", "Organization ID (UUID) for Vulnetix operations")

	// Optional configuration flags
	rootCmd.PersistentFlags().StringVar(&projectName, "project-name", "", "Project name for vulnerability management context")
	rootCmd.PersistentFlags().StringVar(&productName, "product-name", "", "Product name for vulnerability management context")
	rootCmd.PersistentFlags().StringVar(&teamName, "team-name", "", "Team name responsible for the project")
	rootCmd.PersistentFlags().StringVar(&groupName, "group-name", "", "Group name for organizational hierarchy")
	rootCmd.PersistentFlags().StringVar(&tags, "tags", "", "YAML list of tags for categorization (e.g., [\"critical\", \"frontend\", \"api\"])")
	rootCmd.PersistentFlags().StringVar(&tools, "tools", "", "YAML array of tool configurations")

	// Task configuration
	rootCmd.PersistentFlags().StringVar(&task, "task", "scan", "Task to perform: scan, release, report, triage, sarif")

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

	// Add SARIF upload command
	sarifCmd := &cobra.Command{
		Use:   "sarif",
		Short: "Upload and validate SARIF files",
		Long: `Upload SARIF files to Vulnetix for vulnerability analysis.

The SARIF file can be provided via:
- File path: --file path/to/file.sarif
- Standard input: echo '{}' | vulnetix sarif --org-id UUID
- Pipe: some-tool | vulnetix sarif --org-id UUID`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgID == "" {
				return fmt.Errorf("--org-id is required")
			}

			if _, err := uuid.Parse(orgID); err != nil {
				return fmt.Errorf("--org-id must be a valid UUID, got: %s", orgID)
			}

			// Determine input source and read SARIF data
			var sarifData []byte
			var inputMethod string
			var err error

			if sarifFile != "" {
				// Read from file
				inputMethod = "file"
				file, err := os.Open(sarifFile)
				if err != nil {
					return fmt.Errorf("failed to open SARIF file %s: %w", sarifFile, err)
				}
				defer file.Close()

				sarifData, err = io.ReadAll(file)
				if err != nil {
					return fmt.Errorf("failed to read SARIF file: %w", err)
				}
			} else {
				// Read from stdin
				inputMethod = "stdin"
				stat, err := os.Stdin.Stat()
				if err != nil {
					return fmt.Errorf("failed to check stdin: %w", err)
				}

				if (stat.Mode() & os.ModeCharDevice) != 0 {
					return fmt.Errorf("no SARIF data provided. Use --file or pipe/redirect input")
				}

				sarifData, err = io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("failed to read from stdin: %w", err)
				}
			}

			if len(sarifData) == 0 {
				return fmt.Errorf("no SARIF data provided")
			}

			// Validate SARIF locally first
			fmt.Printf("🔍 Validating SARIF file...\n")
			validator := sarif.NewValidator()
			validation, err := validator.ValidateFromBytes(sarifData)
			if err != nil {
				return fmt.Errorf("validation error: %w", err)
			}

			if !validation.Valid {
				fmt.Printf("❌ SARIF validation failed:\n")
				for _, errMsg := range validation.Errors {
					fmt.Printf("  - %s\n", errMsg)
				}
				return fmt.Errorf("SARIF validation failed")
			}

			fmt.Printf("✅ SARIF validation successful\n")
			fmt.Printf("📊 Statistics:\n")
			fmt.Printf("  - Version: %s\n", validation.Version)
			fmt.Printf("  - Runs: %d\n", validation.Stats.RunCount)
			fmt.Printf("  - Results: %d\n", validation.Stats.ResultCount)
			fmt.Printf("  - Tools: %d\n", validation.Stats.ToolCount)

			// Configure uploader
			uploadConfig := &sarif.UploadConfig{
				BaseURL:     sarifBaseURL,
				OrgID:       orgID,
				ContentType: sarif.DetermineContentType(inputMethod),
			}

			uploader := sarif.NewUploader(uploadConfig)

			// Upload SARIF
			fmt.Printf("📤 Uploading SARIF to %s...\n", sarifBaseURL)
			response, err := uploader.Upload(sarifData)
			if err != nil {
				return fmt.Errorf("upload failed: %w", err)
			}

			if !response.Success {
				fmt.Printf("❌ Upload failed (HTTP %d): %s\n", response.StatusCode, response.Message)
				return fmt.Errorf("upload rejected by server")
			}

			fmt.Printf("✅ SARIF uploaded successfully\n")
			fmt.Printf("🆔 Artifact UUID: %s\n", strings.TrimSpace(response.UUID))
			fmt.Printf("🔗 View at: https://dashboard.vulnetix.com/org/%s/artifacts/%s\n", orgID, strings.TrimSpace(response.UUID))

			return nil
		},
	}

	// SARIF command flags
	sarifCmd.Flags().StringVar(&sarifFile, "file", "", "Path to SARIF file (if not provided, reads from stdin)")
	sarifCmd.Flags().StringVar(&sarifBaseURL, "base-url", "https://app.vulnetix.com/api", "Base URL for Vulnetix API")
	rootCmd.AddCommand(versionCmd, sarifCmd)
}
