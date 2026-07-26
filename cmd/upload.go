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
	Short: "Publish a scanner's report to Vulnetix",
	Long: `Publish a SARIF, CycloneDX or SPDX report to Vulnetix.

The report is recorded under the name and version of the tool that produced it,
in the scan category inferred from the report itself, with the same findings,
triage and VEX records a first-party Vulnetix scan produces.

The format is detected from the file's content, not its name: checkov and kics
both write "results.sarif". Reports Vulnetix's own scanners wrote are refused,
because the subcommand that produced one published it when it ran.

In GitHub Actions prefer 'vulnetix gha upload', which publishes every report a
workflow run produced in a single call.

Examples:
  # Publish a third-party tool's report
  vulnetix upload --file gosec.sarif

  # Publish every report in a directory
  vulnetix upload --dir ./reports

  # Publish with an explicit org
  vulnetix upload --file grype.cdx.json --org-id UUID

  # JSON output
  vulnetix upload --json`,
	// Reject an unknown --format before reading the file or contacting the API.
	// Previously the value was forwarded verbatim and only the server objected.
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return upload.ValidateFormat(uploadFormat)
	},
	RunE: runUpload,
}

func runUpload(cmd *cobra.Command, args []string) error {
	ctx := display.FromCommand(cmd)
	t := ctx.Term

	if _, err := auth.LoadCredentials(); err != nil {
		return fmt.Errorf("authentication required: %w\nRun 'vulnetix auth login' to authenticate", err)
	}
	if uploadOrgID != "" {
		if _, err := uuid.Parse(uploadOrgID); err != nil {
			return fmt.Errorf("--org-id must be a valid UUID, got: %s", uploadOrgID)
		}
		orgID = uploadOrgID
	}

	if uploadBaseURL != "" {
		if err := os.Setenv("VULNETIX_API_URL", uploadBaseURL); err != nil {
			return fmt.Errorf("apply --base-url: %w", err)
		}
	}

	submitter, err := newUploadSubmitter(cmd.Context(), ctx, false)
	if err != nil {
		return err
	}

	// Single-file mode
	if uploadFile != "" {
		if _, err := os.Stat(uploadFile); err != nil {
			return fmt.Errorf("cannot access file %s: %w", uploadFile, err)
		}
		progress := ctx.Progress("Publish report", 2)
		progress.SetStage(fmt.Sprintf("Publishing %s", filepath.Base(uploadFile)))

		res, err := publishLocalFile(submitter, uploadFile)
		if err != nil {
			progress.Fail("publish failed")
			return err
		}
		progress.Complete("published")
		printPublishResult(t, uploadFile, res, uploadOutputJSON)
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

	progress := ctx.Progress("Publish reports", len(files))
	progress.SetStage(fmt.Sprintf("Found %d artifact(s) in %s", len(files), discoverDir))

	var failed, published, skipped int
	for i, f := range files {
		fileName := filepath.Base(f.Path)
		progress.Update(i, fmt.Sprintf("Publishing %s (%s)", fileName, f.Format))

		res, err := publishLocalFile(submitter, f.Path)
		switch {
		case err != nil && isAlreadyPublished(err):
			// Discovery mode walks .vulnetix/, which is where Vulnetix's own
			// scanners write. Those were published when they ran, so this is
			// the expected case, not a failure.
			skipped++
			ctx.Logger.Infof("  %s skipped: already published by the scan that produced it", fileName)
		case err != nil:
			failed++
			ctx.Logger.Warnf("  %s failed: %v", fileName, err)
		default:
			published++
			progress.Update(i+1, fmt.Sprintf("Published %s", fileName))
			printPublishResult(t, f.Path, res, uploadOutputJSON)
		}
	}

	if failed > 0 {
		progress.Fail(fmt.Sprintf("%d of %d report(s) failed to publish", failed, len(files)))
		return fmt.Errorf("%d of %d report(s) failed to publish", failed, len(files))
	}
	if published == 0 && skipped > 0 {
		progress.Complete("nothing to publish")
		ctx.Logger.Result(display.WarningMark(t) + fmt.Sprintf(
			" All %d report(s) in %s were already published by the scans that produced them.\n"+
				"Use --file to publish a third-party tool's report.", skipped, discoverDir))
		return nil
	}
	progress.Complete(fmt.Sprintf("published %d report(s)", published))
	return nil
}

// isAlreadyPublished distinguishes "this was Vulnetix's own report" from a real
// failure, so discovery mode does not fail on the directory it defaults to.
func isAlreadyPublished(err error) bool {
	return err != nil && strings.Contains(err.Error(), "published it when it ran")
}

// printPublishResult reports what a report became: the category it was filed
// under, the tool it was attributed to, and the snapshot it can be read at.
//
// The old output named a pipeline id and a processing state, which described
// the blob's journey through a queue rather than anything about the scan.
func printPublishResult(t *display.Terminal, filePath string, res ghaFileResult, asJSON bool) {
	if asJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(res)
		return
	}

	var b strings.Builder
	mark := display.CheckMark(t)
	suffix := " published"
	if res.Status == "duplicate" {
		mark, suffix = display.WarningMark(t), " already published (same scan)"
	}
	b.WriteString(mark + " " + display.Bold(t, filepath.Base(filePath)) + suffix + "\n")

	kv := []display.KVPair{{Key: "Category", Value: res.Category}}
	if res.CategoryWhy != "" {
		kv = append(kv, display.KVPair{Key: "Because", Value: res.CategoryWhy})
	}
	tool := res.Tool
	if res.ToolVersion != "" {
		tool += " " + res.ToolVersion
	}
	if tool != "" {
		kv = append(kv, display.KVPair{Key: "Tool", Value: tool})
	}
	kv = append(kv, display.KVPair{Key: "Findings", Value: fmt.Sprintf("%d", res.Findings)})
	if res.Suppressed > 0 {
		kv = append(kv, display.KVPair{Key: "Suppressed", Value: fmt.Sprintf("%d", res.Suppressed)})
	}
	if res.SnapshotURL != "" {
		kv = append(kv, display.KVPair{Key: "Snapshot", Value: res.SnapshotURL})
	}
	b.WriteString(display.KeyValue(t, kv))
	fmt.Print(b.String())
}

func init() {
	uploadCmd.Flags().StringVar(&uploadFile, "file", "", "Path to a specific artifact file to upload")
	uploadCmd.Flags().StringVar(&uploadDir, "dir", "", "Directory to scan for artifacts (overrides .vulnetix/ discovery)")
	uploadCmd.Flags().StringVar(&uploadOrgID, "org-id", "", "Organization ID (UUID, uses stored credentials if not set)")
	// Kept for the scripts that pass it. It used to address the retired blob
	// endpoint; it now overrides the API base the typed endpoints are called on,
	// which is the same thing VULNETIX_API_URL does.
	uploadCmd.Flags().StringVar(&uploadBaseURL, "base-url", "", "Override the Vulnetix API base URL")
	uploadCmd.Flags().StringVar(&uploadFormat, "format", "", "Override auto-detected format (cyclonedx, spdx, sarif, openvex, csaf_vex)")
	uploadCmd.Flags().BoolVar(&uploadOutputJSON, "json", false, "Output result as JSON")
	_ = uploadCmd.RegisterFlagCompletionFunc("format", cobra.FixedCompletions([]string{"cyclonedx", "spdx", "sarif", "openvex", "csaf_vex"}, cobra.ShellCompDirectiveNoFileComp))
	_ = uploadCmd.MarkFlagFilename("file")

	rootCmd.AddCommand(uploadCmd)
}
