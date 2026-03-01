package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vulnetix/vulnetix/internal/auth"
	"github.com/vulnetix/vulnetix/internal/upload"
)

var (
	uploadFile       string
	uploadOrgID      string
	uploadBaseURL    string
	uploadFormat     string
	uploadOutputJSON bool
)

var uploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload an artifact file to Vulnetix",
	Long: `Upload a security artifact file (SBOM, SARIF, VEX, etc.) to Vulnetix for processing.

The file format is auto-detected from content and extension but can be overridden.
Authentication uses stored credentials or environment variables.

Examples:
  # Upload with stored credentials
  vulnetix upload --file ssvc.cdx.json

  # Upload with explicit org ID
  vulnetix upload --file ssvc.cdx.json --org-id UUID

  # Override format detection
  vulnetix upload --file report.json --format sarif

  # JSON output
  vulnetix upload --file ssvc.cdx.json --json`,
	RunE: runUpload,
}

func runUpload(cmd *cobra.Command, args []string) error {
	if uploadFile == "" {
		return fmt.Errorf("--file is required")
	}

	// Check file exists
	info, err := os.Stat(uploadFile)
	if err != nil {
		return fmt.Errorf("cannot access file %s: %w", uploadFile, err)
	}

	// Load credentials
	creds, err := auth.LoadCredentials()
	if err != nil {
		return fmt.Errorf("authentication required: %w\nRun 'vulnetix auth login' to authenticate", err)
	}

	// Override org ID if provided
	if uploadOrgID != "" {
		if _, err := uuid.Parse(uploadOrgID); err != nil {
			return fmt.Errorf("--org-id must be a valid UUID, got: %s", uploadOrgID)
		}
		creds.OrgID = uploadOrgID
	}

	if !uploadOutputJSON {
		fmt.Printf("Uploading %s (%d bytes)...\n", uploadFile, info.Size())
	}

	// Create upload client
	client := upload.NewClient(uploadBaseURL, creds)

	// Upload file
	result, err := client.UploadFile(uploadFile, uploadFormat)
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}

	if uploadOutputJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	if result.IsDuplicate {
		fmt.Printf("Duplicate file detected (already uploaded)\n")
	} else {
		fmt.Printf("Upload successful\n")
	}
	if result.PipelineRecord != nil {
		fmt.Printf("  Pipeline ID: %s\n", result.PipelineRecord.UUID)
		fmt.Printf("  Detected Type: %s\n", result.PipelineRecord.DetectedType)
		fmt.Printf("  Status: %s\n", result.PipelineRecord.ProcessingState)
	}

	return nil
}

func init() {
	uploadCmd.Flags().StringVar(&uploadFile, "file", "", "Path to artifact file to upload (required)")
	uploadCmd.Flags().StringVar(&uploadOrgID, "org-id", "", "Organization ID (UUID, uses stored credentials if not set)")
	uploadCmd.Flags().StringVar(&uploadBaseURL, "base-url", upload.DefaultBaseURL, "Base URL for Vulnetix API")
	uploadCmd.Flags().StringVar(&uploadFormat, "format", "", "Override auto-detected format (cyclonedx, spdx, sarif, openvex, csaf_vex)")
	uploadCmd.Flags().BoolVar(&uploadOutputJSON, "json", false, "Output result as JSON")
	uploadCmd.MarkFlagRequired("file")

	rootCmd.AddCommand(uploadCmd)
}
