package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vulnetix/vulnetix/internal/github"
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
2. Gathers GitHub Actions metadata (environment variables)
3. Initiates a transaction with Vulnetix API
4. Uploads each artifact with the transaction ID
5. Reports the transaction ID and artifact UUIDs

Example:
  vulnetix gha upload --org-id <uuid>
  vulnetix gha upload --org-id <uuid> --base-url https://api.vulnetix.com`,
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

func runGHAUpload(cmd *cobra.Command, args []string) error {
	// Validate org-id
	if orgID == "" {
		return fmt.Errorf("--org-id is required")
	}

	if _, err := uuid.Parse(orgID); err != nil {
		return fmt.Errorf("--org-id must be a valid UUID, got: %s", orgID)
	}

	// Check if we're in a GitHub Actions environment
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		fmt.Println("⚠️  Warning: Not running in GitHub Actions environment")
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

	fmt.Printf("🚀 Starting GitHub Actions artifact upload\n")
	fmt.Printf("   Organization: %s\n", orgID)
	fmt.Printf("   Repository: %s\n", repository)
	fmt.Printf("   Run ID: %s\n", runID)
	fmt.Println()

	// Create artifact collector
	collector := github.NewArtifactCollector(token, apiURL, repository, runID)

	// List all artifacts
	fmt.Println("📦 Fetching workflow artifacts...")
	ctx := context.Background()
	artifacts, err := collector.ListArtifacts(ctx)
	if err != nil {
		return fmt.Errorf("failed to list artifacts: %w", err)
	}

	if len(artifacts) == 0 {
		fmt.Println("⚠️  No artifacts found in this workflow run")
		return nil
	}

	fmt.Printf("✅ Found %d artifact(s)\n", len(artifacts))
	for i, artifact := range artifacts {
		fmt.Printf("   %d. %s (%d bytes)\n", i+1, artifact.Name, artifact.SizeInBytes)
	}
	fmt.Println()

	// Collect metadata
	artifactNames := make([]string, len(artifacts))
	for i, artifact := range artifacts {
		artifactNames[i] = artifact.Name
	}
	metadata := github.CollectMetadata(artifactNames)

	// Create uploader
	uploader := github.NewArtifactUploader(ghaBaseURL, orgID)

	// Initiate transaction
	fmt.Println("🔄 Initiating upload transaction...")
	txnResp, err := uploader.InitiateTransaction(metadata, artifactNames)
	if err != nil {
		return fmt.Errorf("failed to initiate transaction: %w", err)
	}

	fmt.Printf("✅ Transaction initiated\n")
	fmt.Printf("   Transaction ID: %s\n", txnResp.TxnID)
	fmt.Println()

	// Upload each artifact
	fmt.Println("📤 Uploading artifacts...")
	uploadResults := make([]map[string]string, 0, len(artifacts))

	for i, artifact := range artifacts {
		fmt.Printf("   [%d/%d] Uploading %s...\n", i+1, len(artifacts), artifact.Name)

		// Download and extract artifact
		artifactDir, err := collector.DownloadArtifact(ctx, artifact)
		if err != nil {
			fmt.Printf("      ❌ Failed to download: %v\n", err)
			continue
		}
		defer os.RemoveAll(artifactDir)

		// Upload to Vulnetix
		uploadResp, err := uploader.UploadArtifact(txnResp.TxnID, artifact.Name, artifactDir)
		if err != nil {
			fmt.Printf("      ❌ Failed to upload: %v\n", err)
			continue
		}

		fmt.Printf("      ✅ Uploaded successfully\n")
		fmt.Printf("         UUID: %s\n", uploadResp.UUID)
		fmt.Printf("         Queue Path: %s\n", uploadResp.QueuePath)

		uploadResults = append(uploadResults, map[string]string{
			"name":       artifact.Name,
			"uuid":       uploadResp.UUID,
			"queue_path": uploadResp.QueuePath,
		})
	}

	fmt.Println()
	fmt.Println("✅ Upload complete!")
	fmt.Printf("   Transaction ID: %s\n", txnResp.TxnID)
	fmt.Printf("   Uploaded: %d/%d artifacts\n", len(uploadResults), len(artifacts))
	fmt.Println()
	fmt.Printf("💡 Check status with: vulnetix gha status --org-id %s --txnid %s\n", orgID, txnResp.TxnID)
	fmt.Printf("🔗 View at: https://dashboard.vulnetix.com/org/%s/artifacts\n", orgID)

	// Output JSON if requested
	if ghaOutputJSON {
		output := map[string]interface{}{
			"txnid":    txnResp.TxnID,
			"artifacts": uploadResults,
		}
		jsonData, _ := json.MarshalIndent(output, "", "  ")
		fmt.Println()
		fmt.Println(string(jsonData))
	}

	return nil
}

func runGHAStatus(cmd *cobra.Command, args []string) error {
	// Validate org-id
	if orgID == "" {
		return fmt.Errorf("--org-id is required")
	}

	if _, err := uuid.Parse(orgID); err != nil {
		return fmt.Errorf("--org-id must be a valid UUID, got: %s", orgID)
	}

	// Require either txnid or uuid
	if ghaTxnID == "" && ghaUUID == "" {
		return fmt.Errorf("either --txnid or --uuid is required")
	}

	if ghaTxnID != "" && ghaUUID != "" {
		return fmt.Errorf("only one of --txnid or --uuid can be specified")
	}

	// Create uploader
	uploader := github.NewArtifactUploader(ghaBaseURL, orgID)

	var statusResp *github.StatusResponse
	var err error

	if ghaTxnID != "" {
		fmt.Printf("🔍 Checking transaction status: %s\n", ghaTxnID)
		statusResp, err = uploader.GetTransactionStatus(ghaTxnID)
	} else {
		fmt.Printf("🔍 Checking artifact status: %s\n", ghaUUID)
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
	fmt.Printf("📊 Status: %s\n", statusResp.Status)
	if statusResp.TxnID != "" {
		fmt.Printf("   Transaction ID: %s\n", statusResp.TxnID)
	}
	if statusResp.Message != "" {
		fmt.Printf("   Message: %s\n", statusResp.Message)
	}

	if len(statusResp.Artifacts) > 0 {
		fmt.Println()
		fmt.Printf("📦 Artifacts (%d):\n", len(statusResp.Artifacts))
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
		fmt.Println("📋 Details:")
		for key, value := range statusResp.Details {
			fmt.Printf("   %s: %v\n", key, value)
		}
	}

	fmt.Println()
	fmt.Printf("🔗 View at: https://dashboard.vulnetix.com/org/%s/artifacts\n", orgID)

	return nil
}

func init() {
	// Add upload subcommand
	ghaUploadCmd.Flags().StringVar(&ghaBaseURL, "base-url", "https://api.vulnetix.com", "Base URL for Vulnetix API")
	ghaUploadCmd.Flags().BoolVar(&ghaOutputJSON, "json", false, "Output results as JSON")

	// Add status subcommand
	ghaStatusCmd.Flags().StringVar(&ghaBaseURL, "base-url", "https://api.vulnetix.com", "Base URL for Vulnetix API")
	ghaStatusCmd.Flags().StringVar(&ghaTxnID, "txnid", "", "Transaction ID to check status")
	ghaStatusCmd.Flags().StringVar(&ghaUUID, "uuid", "", "Artifact UUID to check status")
	ghaStatusCmd.Flags().BoolVar(&ghaOutputJSON, "json", false, "Output results as JSON")

	// Add subcommands to gha command
	ghaCmd.AddCommand(ghaUploadCmd, ghaStatusCmd)

	// Add gha command to root
	rootCmd.AddCommand(ghaCmd)
}
