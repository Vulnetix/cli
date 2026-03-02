package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/internal/auth"
	"github.com/vulnetix/cli/internal/github"
	"github.com/vulnetix/cli/internal/upload"
)

var (
	// GHA command flags
	ghaBaseURL    string
	ghaTxnID      string
	ghaUUID       string
	ghaOutputJSON bool
)

// ghaCmd represents the gha command for GitHub Actions artifact management
var ghaCmd = &cobra.Command{
	Use:   "gha",
	Short: "GitHub Actions artifact management",
	Long: `Manage GitHub Actions artifacts for Vulnetix.

This command allows you to upload workflow artifacts to Vulnetix and check their status.
It is designed to work within GitHub Actions workflows.`,
}

// ghaUploadCmd handles uploading artifacts from GitHub Actions
var ghaUploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload GitHub Actions artifacts to Vulnetix",
	Long: `Upload all artifacts from the current GitHub Actions workflow run to Vulnetix.

This command:
1. Collects all artifacts from the current workflow run
2. Downloads and extracts each artifact
3. Uploads each file using the standard Vulnetix upload API
4. Reports the pipeline UUIDs for each uploaded file

Example:
  vulnetix gha upload --org-id <uuid>
  vulnetix gha upload --org-id <uuid> --base-url https://app.vulnetix.com/api`,
	RunE: runGHAUpload,
}

// ghaStatusCmd handles checking status of uploads
var ghaStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check status of artifact uploads",
	Long: `Check the status of artifact uploads using transaction ID or artifact UUID.

You can check status using either:
- Transaction ID (--txnid): Shows status of all artifacts in the transaction
- Artifact UUID (--uuid): Shows status of a specific artifact

Examples:
  vulnetix gha status --org-id <uuid> --txnid <transaction-id>
  vulnetix gha status --org-id <uuid> --uuid <artifact-uuid>
  vulnetix gha status --org-id <uuid> --txnid <txn-id> --json`,
	RunE: runGHAStatus,
}

func resolveOrgID() (string, error) {
	if orgID != "" {
		if _, err := uuid.Parse(orgID); err != nil {
			return "", fmt.Errorf("--org-id must be a valid UUID, got: %s", orgID)
		}
		return orgID, nil
	}

	// Try loading from stored credentials
	creds, err := auth.LoadCredentials()
	if err != nil || creds == nil {
		return "", fmt.Errorf("--org-id is required (no stored credentials found)")
	}
	if creds.OrgID == "" {
		return "", fmt.Errorf("--org-id is required (stored credentials have no org ID)")
	}
	return creds.OrgID, nil
}

func runGHAUpload(cmd *cobra.Command, args []string) error {
	resolvedOrgID, err := resolveOrgID()
	if err != nil {
		return err
	}
	orgID = resolvedOrgID

	// Check if we're in a GitHub Actions environment
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		fmt.Println("Warning: Not running in GitHub Actions environment")
	}

	// Get GitHub context
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("GITHUB_TOKEN environment variable is required")
	}

	apiURL := os.Getenv("GITHUB_API_URL")
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}

	repository := os.Getenv("GITHUB_REPOSITORY")
	if repository == "" {
		return fmt.Errorf("GITHUB_REPOSITORY environment variable is required")
	}

	runID := os.Getenv("GITHUB_RUN_ID")
	if runID == "" {
		return fmt.Errorf("GITHUB_RUN_ID environment variable is required")
	}

	fmt.Printf("Starting GitHub Actions artifact upload\n")
	fmt.Printf("   Organization: %s\n", orgID)
	fmt.Printf("   Repository: %s\n", repository)
	fmt.Printf("   Run ID: %s\n", runID)
	fmt.Println()

	// Create artifact collector
	collector := github.NewArtifactCollector(token, apiURL, repository, runID)

	// List all artifacts
	fmt.Println("Fetching workflow artifacts...")
	ctx := cmd.Context()
	artifacts, err := collector.ListArtifacts(ctx)
	if err != nil {
		return fmt.Errorf("failed to list artifacts: %w", err)
	}

	if len(artifacts) == 0 {
		fmt.Println("Warning: No artifacts found in this workflow run")
		return nil
	}

	fmt.Printf("Found %d artifact(s)\n", len(artifacts))
	for i, artifact := range artifacts {
		fmt.Printf("   %d. %s (%d bytes)\n", i+1, artifact.Name, artifact.SizeInBytes)
	}
	fmt.Println()

	// Load credentials for upload client
	creds, err := auth.LoadCredentials()
	if err != nil {
		return fmt.Errorf("authentication required: %w\nRun 'vulnetix auth login' first", err)
	}
	if creds != nil {
		creds.OrgID = orgID
	}

	// Create upload client (same API as 'vulnetix upload')
	uploadClient := upload.NewClient(ghaBaseURL, creds)

	// Download and upload each artifact
	fmt.Println("Uploading artifacts...")
	type uploadResult struct {
		Name       string `json:"name"`
		File       string `json:"file"`
		PipelineID string `json:"pipelineId,omitempty"`
		Status     string `json:"status"`
		Error      string `json:"error,omitempty"`
	}
	var results []uploadResult

	for i, artifact := range artifacts {
		fmt.Printf("   [%d/%d] Processing %s...\n", i+1, len(artifacts), artifact.Name)

		// Download and extract artifact from GitHub
		artifactDir, err := collector.DownloadArtifact(ctx, artifact)
		if err != nil {
			fmt.Printf("      Failed to download: %v\n", err)
			results = append(results, uploadResult{
				Name:   artifact.Name,
				Status: "error",
				Error:  err.Error(),
			})
			continue
		}

		// Find all files in the extracted artifact directory
		files, err := findFiles(artifactDir)
		if err != nil {
			os.RemoveAll(artifactDir)
			fmt.Printf("      Failed to read files: %v\n", err)
			results = append(results, uploadResult{
				Name:   artifact.Name,
				Status: "error",
				Error:  err.Error(),
			})
			continue
		}

		// Upload each file using the standard upload API
		for _, filePath := range files {
			fileName := filepath.Base(filePath)
			fmt.Printf("      Uploading %s...\n", fileName)

			resp, err := uploadClient.UploadFile(filePath, "")
			if err != nil {
				fmt.Printf("      Failed to upload %s: %v\n", fileName, err)
				results = append(results, uploadResult{
					Name:   artifact.Name,
					File:   fileName,
					Status: "error",
					Error:  err.Error(),
				})
				continue
			}

			pipelineID := ""
			if resp.PipelineRecord != nil {
				pipelineID = resp.PipelineRecord.UUID
			}

			status := "uploaded"
			if resp.IsDuplicate {
				status = "duplicate"
			}

			fmt.Printf("      Uploaded %s (pipeline: %s)\n", fileName, pipelineID)
			results = append(results, uploadResult{
				Name:       artifact.Name,
				File:       fileName,
				PipelineID: pipelineID,
				Status:     status,
			})
		}

		os.RemoveAll(artifactDir)
	}

	fmt.Println()

	successCount := 0
	for _, r := range results {
		if r.Status != "error" {
			successCount++
		}
	}
	fmt.Printf("Upload complete: %d/%d files uploaded successfully\n", successCount, len(results))

	// Output JSON if requested
	if ghaOutputJSON {
		output := map[string]interface{}{
			"artifacts": results,
			"total":     len(results),
			"success":   successCount,
		}
		jsonData, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON output: %w", err)
		}
		fmt.Println()
		fmt.Println(string(jsonData))
	}

	return nil
}

// findFiles recursively finds all files in a directory
func findFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func runGHAStatus(cmd *cobra.Command, args []string) error {
	resolvedOrgID, err := resolveOrgID()
	if err != nil {
		return err
	}
	orgID = resolvedOrgID

	// Require either txnid or uuid
	if ghaTxnID == "" && ghaUUID == "" {
		return fmt.Errorf("either --txnid or --uuid is required")
	}

	if ghaTxnID != "" && ghaUUID != "" {
		return fmt.Errorf("only one of --txnid or --uuid can be specified")
	}

	// Create uploader for status checks
	uploader := github.NewArtifactUploader(ghaBaseURL, orgID)

	var statusResp *github.StatusResponse

	if ghaTxnID != "" {
		fmt.Printf("Checking transaction status: %s\n", ghaTxnID)
		statusResp, err = uploader.GetTransactionStatus(ghaTxnID)
	} else {
		fmt.Printf("Checking artifact status: %s\n", ghaUUID)
		statusResp, err = uploader.GetArtifactStatus(ghaUUID)
	}

	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	// Output JSON if requested
	if ghaOutputJSON {
		jsonData, err := json.MarshalIndent(statusResp, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonData))
		return nil
	}

	// Pretty print status
	fmt.Println()
	fmt.Printf("Status: %s\n", statusResp.Status)
	if statusResp.TxnID != "" {
		fmt.Printf("   Transaction ID: %s\n", statusResp.TxnID)
	}
	if statusResp.Message != "" {
		fmt.Printf("   Message: %s\n", statusResp.Message)
	}

	if len(statusResp.Artifacts) > 0 {
		fmt.Println()
		fmt.Printf("Artifacts (%d):\n", len(statusResp.Artifacts))
		for i, artifact := range statusResp.Artifacts {
			fmt.Printf("   %d. %s\n", i+1, artifact.Name)
			fmt.Printf("      UUID: %s\n", artifact.UUID)
			fmt.Printf("      Status: %s\n", artifact.Status)
			if artifact.QueuePath != "" {
				fmt.Printf("      Queue Path: %s\n", artifact.QueuePath)
			}
			if artifact.Error != "" {
				fmt.Printf("      Error: %s\n", artifact.Error)
			}
		}
	}

	if len(statusResp.Details) > 0 {
		fmt.Println()
		fmt.Println("Details:")
		for key, value := range statusResp.Details {
			fmt.Printf("   %s: %v\n", key, value)
		}
	}

	return nil
}

func init() {
	// Add upload subcommand
	ghaUploadCmd.Flags().StringVar(&ghaBaseURL, "base-url", upload.DefaultBaseURL, "Base URL for Vulnetix API")
	ghaUploadCmd.Flags().BoolVar(&ghaOutputJSON, "json", false, "Output results as JSON")

	// Add status subcommand
	ghaStatusCmd.Flags().StringVar(&ghaBaseURL, "base-url", upload.DefaultBaseURL, "Base URL for Vulnetix API")
	ghaStatusCmd.Flags().StringVar(&ghaTxnID, "txnid", "", "Transaction ID to check status")
	ghaStatusCmd.Flags().StringVar(&ghaUUID, "uuid", "", "Artifact UUID to check status")
	ghaStatusCmd.Flags().BoolVar(&ghaOutputJSON, "json", false, "Output results as JSON")

	// Add subcommands to gha command
	ghaCmd.AddCommand(ghaUploadCmd, ghaStatusCmd)

	// Add gha command to root
	rootCmd.AddCommand(ghaCmd)
}
