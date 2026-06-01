package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/upload"
	"github.com/vulnetix/cli/v3/pkg/auth"
)

var (
	uploadFile       string
	uploadDir        string
	uploadOrgID      string
	uploadBaseURL    string
	uploadFormat     string
	uploadOutputJSON bool
)

var uploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload artifact files to Vulnetix",
	Long: `Upload security artifact files (SBOMs, SARIF, VEX, etc.) to Vulnetix for processing.

By default, upload discovers all artifacts in the .vulnetix/ directory (project-relative
first, then ~/.vulnetix/) and uploads each one after local schema validation.

The file format is auto-detected from content and extension. CycloneDX files are
validated against the embedded JSON schema before upload.

Examples:
  # Upload all artifacts from .vulnetix/ (default)
  vulnetix upload

  # Upload a specific file
  vulnetix upload --file sbom.cdx.json

  # Upload all artifacts from a custom directory
  vulnetix upload --dir /path/to/artifacts

  # Upload with explicit org ID
  vulnetix upload --file sbom.cdx.json --org-id UUID

  # JSON output
  vulnetix upload --json`,
	RunE: runUpload,
}

func runUpload(cmd *cobra.Command, args []string) error {
	ctx := display.FromCommand(cmd)
	t := ctx.Term

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

	// Create upload client
	client := upload.NewClient(uploadBaseURL, creds)

	// Single-file mode
	if uploadFile != "" {
		info, err := os.Stat(uploadFile)
		if err != nil {
			return fmt.Errorf("cannot access file %s: %w", uploadFile, err)
		}
		total := 3
		if info.Size() >= upload.ChunkThreshold {
			total = int((info.Size()+upload.DefaultChunkSize-1)/upload.DefaultChunkSize) + 2
		}
		progress := ctx.Progress("Upload artifact", total)
		progress.SetStage(fmt.Sprintf("Preparing %s (%d bytes)", filepath.Base(uploadFile), info.Size()))

		result, err := client.UploadFileWithProgress(uploadFile, uploadFormat, func(done, total int, stage string) {
			progress.Update(done, fmt.Sprintf("%s: %s", filepath.Base(uploadFile), stage))
		})
		if err != nil {
			progress.Fail("upload failed")
			return fmt.Errorf("upload failed: %w", err)
		}
		progress.Complete("upload complete")
		printUploadResult(t, uploadFile, result, uploadOutputJSON)
		return nil
	}

	// Discover artifacts from a directory
	var discoverDir string
	if uploadDir != "" {
		discoverDir = uploadDir
	} else {
		found, ok := upload.FindVulnetixDir()
		if !ok {
			ctx.Logger.Result(display.WarningMark(t) + " No .vulnetix/ directory found.\n" +
				"Run 'vulnetix scan' to generate artifacts, then 'vulnetix upload'.\n" +
				"Or use --file to specify a file directly.")
			return nil
		}
		discoverDir = found
	}

	files, warnings, err := upload.DiscoverVulnetixFiles(discoverDir)
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}

	for _, w := range warnings {
		ctx.Logger.Infof("warning: %s", w)
	}

	if len(files) == 0 {
		ctx.Logger.Result(display.WarningMark(t) + fmt.Sprintf(" No uploadable artifacts found in %s.\n", discoverDir) +
			"Run 'vulnetix scan' to generate artifacts, then 'vulnetix upload'.\n" +
			"Or use --file to specify a file directly.")
		return nil
	}

	progress := ctx.Progress("Upload artifacts", len(files))
	progress.SetStage(fmt.Sprintf("Found %d artifact(s) in %s", len(files), discoverDir))

	var anyError bool
	for i, f := range files {
		info, err := os.Stat(f.Path)
		if err != nil {
			progress.SetStage(fmt.Sprintf("Skipping %s: %v", filepath.Base(f.Path), err))
			anyError = true
			continue
		}
		fileName := filepath.Base(f.Path)
		progress.Update(i, fmt.Sprintf("Uploading %s (%d bytes, format: %s)", fileName, info.Size(), f.Format))

		result, err := client.UploadFileWithProgress(f.Path, f.Format, func(done, total int, stage string) {
			progress.SetStage(fmt.Sprintf("%s: %s %d/%d", fileName, stage, done, total))
		})
		if err != nil {
			progress.SetStage(fmt.Sprintf("%s failed: %v", fileName, err))
			anyError = true
			continue
		}
		progress.Update(i+1, fmt.Sprintf("Uploaded %s", fileName))
		printUploadResult(t, f.Path, result, uploadOutputJSON)
	}

	if anyError {
		progress.Fail("one or more uploads failed")
		return fmt.Errorf("one or more uploads failed")
	}
	progress.Complete("all artifacts uploaded")
	return nil
}

func printUploadResult(t *display.Terminal, filePath string, result *upload.FinalizeResponse, asJSON bool) {
	if asJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(result)
		return
	}

	var b strings.Builder
	if result.IsDuplicate {
		b.WriteString(display.WarningMark(t) + " " + display.Bold(t, filepath.Base(filePath)) + " — duplicate (already uploaded)\n")
	} else {
		b.WriteString(display.CheckMark(t) + " " + display.Bold(t, filepath.Base(filePath)) + " — uploaded successfully\n")
	}
	if result.PipelineRecord != nil {
		b.WriteString(display.KeyValue(t, []display.KVPair{
			{Key: "Pipeline ID", Value: result.PipelineRecord.UUID},
			{Key: "Detected Type", Value: result.PipelineRecord.DetectedType},
			{Key: "Status", Value: result.PipelineRecord.ProcessingState},
		}))
	}
	fmt.Print(b.String())
}

func init() {
	uploadCmd.Flags().StringVar(&uploadFile, "file", "", "Path to a specific artifact file to upload")
	uploadCmd.Flags().StringVar(&uploadDir, "dir", "", "Directory to scan for artifacts (overrides .vulnetix/ discovery)")
	uploadCmd.Flags().StringVar(&uploadOrgID, "org-id", "", "Organization ID (UUID, uses stored credentials if not set)")
	uploadCmd.Flags().StringVar(&uploadBaseURL, "base-url", upload.DefaultBaseURL, "Base URL for Vulnetix API")
	uploadCmd.Flags().StringVar(&uploadFormat, "format", "", "Override auto-detected format (cyclonedx, spdx, sarif, openvex, csaf_vex)")
	uploadCmd.Flags().BoolVar(&uploadOutputJSON, "json", false, "Output result as JSON")
	_ = uploadCmd.RegisterFlagCompletionFunc("format", cobra.FixedCompletions([]string{"cyclonedx", "spdx", "sarif", "openvex", "csaf_vex"}, cobra.ShellCompDirectiveNoFileComp))
	_ = uploadCmd.MarkFlagFilename("file")

	rootCmd.AddCommand(uploadCmd)
}
