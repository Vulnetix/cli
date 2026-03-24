package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/internal/cdx"
	"github.com/vulnetix/cli/internal/gitctx"
	"github.com/vulnetix/cli/internal/scan"
	"github.com/vulnetix/cli/internal/tty"
	"github.com/vulnetix/cli/internal/tui"
	"github.com/vulnetix/cli/internal/vdb"
)

// scanCmd is the top-level scan command with auto-discovery
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan local files for vulnerabilities using the VDB API",
	Long: `Scan local manifest files and SBOMs for vulnerabilities.

By default, auto-discovers manifest files (package-lock.json, go.sum, Cargo.lock, etc.)
and SBOM documents (SPDX, CycloneDX) by walking the current directory.

Use --file to scan a single file, or --path to specify a different root directory.

In interactive terminals, displays a rich TUI with progress tracking and navigable
results. In non-interactive mode (CI/CD, pipes), outputs CycloneDX 1.7 JSON by default.

Requires VDB API credentials (same as vdb commands). Always uses API v2.

Examples:
  vulnetix scan
  vulnetix scan --path ./myproject
  vulnetix scan --depth 5
  vulnetix scan --file package-lock.json
  vulnetix scan --file sbom.json --type cyclonedx
  vulnetix scan --exclude "test*" --exclude "vendor"
  vulnetix scan --no-poll
  vulnetix scan -f json
  vulnetix scan -f cdx16
  vulnetix scan --concurrency 3`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return resolveVDBCredentials(true)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		singleFile, _ := cmd.Flags().GetString("file")
		scanPath, _ := cmd.Flags().GetString("path")
		depth, _ := cmd.Flags().GetInt("depth")
		fileType, _ := cmd.Flags().GetString("type")
		manifestType, _ := cmd.Flags().GetString("manifest-type")
		ecosystem, _ := cmd.Flags().GetString("ecosystem")
		noPoll, _ := cmd.Flags().GetBool("no-poll")
		pollInterval, _ := cmd.Flags().GetInt("poll-interval")
		excludes, _ := cmd.Flags().GetStringArray("exclude")
		output, _ := cmd.Flags().GetString("output")
		outputFmt, _ := cmd.Flags().GetString("format")
		concurrency, _ := cmd.Flags().GetInt("concurrency")

		// Force V2 for scan
		vdbAPIVersion = "v2"

		client := newVDBClient()

		// Single file mode (backward compat — uses old sequential path)
		if singleFile != "" {
			return scanSingleFile(client, singleFile, fileType, manifestType, ecosystem, noPoll, pollInterval, output)
		}

		// Auto-discovery mode
		if scanPath == "" {
			scanPath = "."
		}

		fmt.Fprintf(os.Stderr, "Scanning %s (depth: %d)...\n\n", scanPath, depth)

		files, err := scan.WalkForScanFiles(scan.WalkOptions{
			RootPath: scanPath,
			MaxDepth: depth,
			Excludes: excludes,
		})
		if err != nil {
			return fmt.Errorf("failed to scan directory: %w", err)
		}

		if len(files) == 0 {
			fmt.Fprintln(os.Stderr, "No scannable files detected.")
			return nil
		}

		// Display detected files
		fmt.Fprintln(os.Stderr, "Detected files:")
		var uploadable []scan.DetectedFile
		for _, f := range files {
			switch f.FileType {
			case scan.FileTypeManifest:
				lockStr := ""
				if f.ManifestInfo.IsLock {
					lockStr = "lock"
				}
				supportedStr := ""
				if !f.Supported {
					supportedStr = " [not supported by backend]"
				}
				fmt.Fprintf(os.Stderr, "  %-40s manifest    %-10s (%-12s) %s%s\n",
					f.RelPath, f.ManifestInfo.Ecosystem, f.ManifestInfo.Language, lockStr, supportedStr)
			case scan.FileTypeSPDX:
				validStr := "valid"
				if !f.Supported {
					validStr = "unsupported version"
				}
				fmt.Fprintf(os.Stderr, "  %-40s spdx       %-10s              %s\n",
					f.RelPath, f.SBOMVersion, validStr)
			case scan.FileTypeCycloneDX:
				validStr := "valid"
				if !f.Supported {
					validStr = "unsupported version"
				}
				fmt.Fprintf(os.Stderr, "  %-40s cyclonedx  v%-9s              %s\n",
					f.RelPath, f.SBOMVersion, validStr)
			}

			if f.Supported {
				uploadable = append(uploadable, f)
			}
		}

		if len(uploadable) == 0 {
			fmt.Fprintln(os.Stderr, "\nNo supported files found for scanning.")
			return nil
		}

		// Collect git context (shared across all uploads)
		gitCtx := gitctx.Collect(scanPath)
		repoRoot := ""
		if gitCtx != nil {
			repoRoot = gitCtx.RepoRootPath
			commitShort := gitCtx.CurrentCommit
			if len(commitShort) > 8 {
				commitShort = commitShort[:8]
			}
			remote := ""
			if len(gitCtx.RemoteURLs) > 0 {
				remote = gitCtx.RemoteURLs[0]
			}
			fmt.Fprintf(os.Stderr, "\nGit: %s @ %s (%s)\n", gitCtx.CurrentBranch, commitShort, remote)
		}

		// Determine output format (new --format flag takes precedence over --output)
		if outputFmt == "" {
			// Map legacy --output values
			switch output {
			case "json":
				outputFmt = "json"
			default:
				outputFmt = "cdx17"
			}
		}

		// Branch: interactive TUI vs non-interactive
		interactive := tty.IsInteractive() && !noPoll
		_ = concurrency // used by engines below

		if interactive {
			return runInteractiveScan(client, uploadable, pollInterval, outputFmt, concurrency, gitCtx, repoRoot)
		}
		return runNonInteractiveScan(client, uploadable, noPoll, pollInterval, outputFmt, concurrency, gitCtx, repoRoot)
	},
}

// scanStatusCmd checks the status of a scan
var scanStatusCmd = &cobra.Command{
	Use:   "status <scan-id>",
	Short: "Check the status of a scan",
	Long: `Check the status of a previously submitted scan.

Examples:
  vulnetix scan status abc123
  vulnetix scan status abc123 --poll
  vulnetix scan status abc123 --poll --poll-interval 10`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		scanID := args[0]
		poll, _ := cmd.Flags().GetBool("poll")
		pollInterval, _ := cmd.Flags().GetInt("poll-interval")
		output, _ := cmd.Flags().GetString("output")

		// Force V2
		vdbAPIVersion = "v2"

		client := newVDBClient()

		if poll {
			return pollScanResultsLegacy(client, []string{scanID}, pollInterval, output)
		}

		result, err := client.V2ScanStatus(scanID)
		if err != nil {
			return fmt.Errorf("failed to get scan status: %w", err)
		}
		printRateLimit(client)
		return printOutput(result, output)
	},
}

// runInteractiveScan launches the bubbletea TUI for interactive scan experience.
func runInteractiveScan(client *vdb.Client, files []scan.DetectedFile, pollInterval int, outputFmt string, _ int, gitCtx *gitctx.GitContext, repoRoot string) error {
	fmt.Fprintf(os.Stderr, "\nStarting interactive scan of %d file(s)...\n\n", len(files))
	return tui.Run(client, files, pollInterval, outputFmt, gitCtx, repoRoot)
}

// runNonInteractiveScan runs the scan with concurrent uploads and stderr progress,
// then outputs structured data to stdout.
func runNonInteractiveScan(client *vdb.Client, files []scan.DetectedFile, noPoll bool, pollInterval int, outputFmt string, concurrency int, gitCtx *gitctx.GitContext, repoRoot string) error {
	ctx := context.Background()

	fmt.Fprintf(os.Stderr, "\nUploading %d file(s) to VDB API v2...\n\n", len(files))

	// Concurrent upload with stderr progress
	engine := &scan.UploadEngine{
		Client:      client,
		Concurrency: concurrency,
		GitContext:  gitCtx,
		RepoRoot:    repoRoot,
		OnProgress: func(t *scan.ScanTask) {
			switch t.Status {
			case "uploading":
				fmt.Fprintf(os.Stderr, "  %-40s uploading...\n", t.File.RelPath)
			case "uploaded":
				fmt.Fprintf(os.Stderr, "  %-40s scan-id: %s (%.1fs)\n",
					t.File.RelPath, t.ScanID, t.UploadDuration().Seconds())
			case "error":
				fmt.Fprintf(os.Stderr, "  %-40s ERROR: %v\n", t.File.RelPath, t.Error)
			}
		},
	}

	tasks := engine.UploadAll(ctx, files)

	// Collect scan IDs
	var hasScans bool
	for _, t := range tasks {
		if t.ScanID != "" {
			hasScans = true
			break
		}
	}

	if !hasScans {
		return fmt.Errorf("no scans were submitted successfully")
	}

	if noPoll {
		fmt.Fprintln(os.Stderr, "\nScan IDs (use 'vulnetix scan status <id> --poll' to check results):")
		for _, t := range tasks {
			if t.ScanID != "" {
				fmt.Println(t.ScanID)
			}
		}
		return nil
	}

	// Concurrent polling with stderr progress
	fmt.Fprintf(os.Stderr, "\nPolling for results (interval: %ds)...\n\n", pollInterval)

	// Track which files have been printed as "polling" to avoid duplicate lines
	pollingSeen := make(map[string]bool)
	var pollMu sync.Mutex

	poller := &scan.PollEngine{
		Client:   client,
		Interval: time.Duration(pollInterval) * time.Second,
		OnProgress: func(t *scan.ScanTask) {
			pollMu.Lock()
			defer pollMu.Unlock()

			switch t.Status {
			case "polling":
				if !pollingSeen[t.File.RelPath] {
					pollingSeen[t.File.RelPath] = true
					fmt.Fprintf(os.Stderr, "  %-40s processing... [%s]\n", t.File.RelPath, t.ScanID)
				}
			case "complete":
				vulnCount := len(t.Vulns)
				fmt.Fprintf(os.Stderr, "  %-40s %d vulns found (%.1fs)\n",
					t.File.RelPath, vulnCount, t.TotalDuration().Seconds())
			case "error":
				fmt.Fprintf(os.Stderr, "  %-40s ERROR: %v (%.1fs)\n",
					t.File.RelPath, t.Error, t.TotalDuration().Seconds())
			}
		},
	}

	poller.PollAll(ctx, tasks)

	// Print summary to stderr
	summary := scan.Summarize(tasks)
	fmt.Fprintf(os.Stderr, "\n%s\n\n", summary.FormatSummary())

	printRateLimit(client)

	// Output results to stdout
	return writeOutput(tasks, outputFmt)
}

// writeOutput writes scan results to stdout in the requested format.
func writeOutput(tasks []*scan.ScanTask, format string) error {
	specVersion, isRaw := cdx.NormalizeFormat(format)

	if isRaw {
		return writeRawJSON(tasks)
	}
	return writeCycloneDX(tasks, specVersion)
}

func writeCycloneDX(tasks []*scan.ScanTask, specVersion string) error {
	bom := cdx.BuildFromScanTasks(tasks, specVersion)
	return bom.WriteJSON(os.Stdout)
}

func writeRawJSON(tasks []*scan.ScanTask) error {
	results := make(map[string]interface{})
	for _, t := range tasks {
		if t.RawResult != nil {
			key := t.File.RelPath
			if key == "" {
				key = t.ScanID
			}
			results[key] = t.RawResult
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(results)
}

// scanSingleFile handles --file mode (backward compatible, sequential)
func scanSingleFile(client *vdb.Client, filePath, fileType, manifestType, ecosystem string, noPoll bool, pollInterval int, output string) error {
	var result map[string]interface{}
	var err error

	// Determine file type
	switch fileType {
	case "spdx":
		fmt.Fprintf(os.Stderr, "Uploading SPDX document: %s\n", filePath)
		result, err = client.V2ScanSPDX(filePath)
	case "cyclonedx":
		fmt.Fprintf(os.Stderr, "Uploading CycloneDX document: %s\n", filePath)
		result, err = client.V2ScanCycloneDX(filePath)
	case "manifest", "":
		// Auto-detect or use explicit manifest type
		if manifestType == "" {
			if info, ok := scan.DetectManifest(filePath); ok {
				manifestType = info.Type
				if ecosystem == "" {
					ecosystem = info.Ecosystem
				}
			} else {
				// Try SBOM detection
				sbomType, _, supported := scan.DetectSBOM(filePath)
				switch sbomType {
				case scan.FileTypeSPDX:
					if !supported {
						return fmt.Errorf("SPDX version not supported")
					}
					fmt.Fprintf(os.Stderr, "Uploading SPDX document: %s\n", filePath)
					result, err = client.V2ScanSPDX(filePath)
					if err != nil {
						return fmt.Errorf("failed to scan file: %w", err)
					}
					return handleScanResult(client, result, noPoll, pollInterval, output)
				case scan.FileTypeCycloneDX:
					if !supported {
						return fmt.Errorf("CycloneDX version not supported")
					}
					fmt.Fprintf(os.Stderr, "Uploading CycloneDX document: %s\n", filePath)
					result, err = client.V2ScanCycloneDX(filePath)
					if err != nil {
						return fmt.Errorf("failed to scan file: %w", err)
					}
					return handleScanResult(client, result, noPoll, pollInterval, output)
				default:
					return fmt.Errorf("unable to detect file type for %s; use --type or --manifest-type to specify", filePath)
				}
			}
		}

		if !scan.SupportedManifestTypes[manifestType] {
			return fmt.Errorf("manifest type %q is not supported by the backend", manifestType)
		}

		fmt.Fprintf(os.Stderr, "Uploading manifest: %s (type: %s)\n", filePath, manifestType)
		result, err = client.V2ScanManifest(filePath, manifestType, ecosystem)
	default:
		return fmt.Errorf("unknown file type %q; use manifest, spdx, or cyclonedx", fileType)
	}

	if err != nil {
		return fmt.Errorf("failed to scan file: %w", err)
	}

	return handleScanResult(client, result, noPoll, pollInterval, output)
}

func handleScanResult(client *vdb.Client, result map[string]interface{}, noPoll bool, pollInterval int, output string) error {
	printRateLimit(client)

	scanID := ""
	if id, ok := result["scanId"].(string); ok {
		scanID = id
	}

	if scanID == "" {
		return printOutput(result, output)
	}

	if noPoll {
		fmt.Fprintf(os.Stderr, "Scan submitted: %s\n", scanID)
		fmt.Println(scanID)
		return nil
	}

	fmt.Fprintf(os.Stderr, "Scan submitted: %s -- polling for results...\n", scanID)
	return pollScanResultsLegacy(client, []string{scanID}, pollInterval, output)
}

// pollScanResultsLegacy is the original sequential polling used by scan status subcommand.
func pollScanResultsLegacy(client *vdb.Client, scanIDs []string, intervalSec int, output string) error {
	pending := make(map[string]bool)
	for _, id := range scanIDs {
		pending[id] = true
	}

	allResults := make(map[string]interface{})
	interval := time.Duration(intervalSec) * time.Second

	for len(pending) > 0 {
		for id := range pending {
			result, err := client.V2ScanStatus(id)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  [%s] error: %v\n", id, err)
				delete(pending, id)
				allResults[id] = map[string]interface{}{"error": err.Error()}
				continue
			}

			status, _ := result["status"].(string)
			switch status {
			case "complete", "completed", "error", "failed":
				fmt.Fprintf(os.Stderr, "  [%s] %s\n", id, status)
				delete(pending, id)
				allResults[id] = result
			default:
				fmt.Fprintf(os.Stderr, "  [%s] %s...\n", id, status)
			}
		}

		if len(pending) > 0 {
			time.Sleep(interval)
		}
	}

	// Print final results
	if len(allResults) == 1 {
		for _, v := range allResults {
			return printOutput(v, output)
		}
	}
	return printOutput(allResults, output)
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.AddCommand(scanStatusCmd)

	// Scan flags
	scanCmd.Flags().String("path", ".", "Directory to scan")
	scanCmd.Flags().Int("depth", 3, "Max recursion depth")
	scanCmd.Flags().String("file", "", "Scan a single file (skip discovery)")
	scanCmd.Flags().String("type", "", "Override file type: manifest, spdx, cyclonedx")
	scanCmd.Flags().String("manifest-type", "", "Override manifest type (e.g. package-lock.json)")
	scanCmd.Flags().String("ecosystem", "", "Override ecosystem for manifest scan")
	scanCmd.Flags().Bool("no-poll", false, "Print scan IDs without waiting for results")
	scanCmd.Flags().Int("poll-interval", 5, "Polling interval in seconds")
	scanCmd.Flags().StringArray("exclude", nil, "Exclude paths matching glob (repeatable)")
	scanCmd.Flags().StringP("output", "o", "pretty", "Output format for legacy/status mode (json, pretty)")
	scanCmd.Flags().StringP("format", "f", "", "Output format: cdx17 (default), cdx16, json")
	scanCmd.Flags().Int("concurrency", 5, "Max concurrent uploads")

	// Scan status flags
	scanStatusCmd.Flags().Bool("poll", false, "Poll until complete")
	scanStatusCmd.Flags().Int("poll-interval", 5, "Polling interval in seconds")
	scanStatusCmd.Flags().StringP("output", "o", "pretty", "Output format (json, pretty)")
}
