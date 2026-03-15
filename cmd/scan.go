package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/internal/scan"
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

Requires VDB API credentials (same as vdb commands). Always uses API v2.

Examples:
  vulnetix scan
  vulnetix scan --path ./myproject
  vulnetix scan --depth 5
  vulnetix scan --file package-lock.json
  vulnetix scan --file sbom.json --type cyclonedx
  vulnetix scan --exclude "test*" --exclude "vendor"
  vulnetix scan --no-poll`,
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

		// Force V2 for scan
		vdbAPIVersion = "v2"

		client := newVDBClient()

		// Single file mode
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

		fmt.Fprintf(os.Stderr, "\nUploading %d file(s) to VDB API v2...\n\n", len(uploadable))

		// Upload each file and collect scan IDs
		type scanResult struct {
			File   scan.DetectedFile
			ScanID string
			Error  error
		}
		var results []scanResult

		for _, f := range uploadable {
			var result map[string]interface{}
			var err error

			switch f.FileType {
			case scan.FileTypeManifest:
				result, err = client.V2ScanManifest(f.Path, f.ManifestInfo.Type, f.ManifestInfo.Ecosystem)
			case scan.FileTypeSPDX:
				result, err = client.V2ScanSPDX(f.Path)
			case scan.FileTypeCycloneDX:
				result, err = client.V2ScanCycloneDX(f.Path)
			}

			if err != nil {
				fmt.Fprintf(os.Stderr, "  %-40s ERROR: %v\n", f.RelPath, err)
				results = append(results, scanResult{File: f, Error: err})
				continue
			}

			scanID := ""
			if id, ok := result["scanId"].(string); ok {
				scanID = id
			}

			fmt.Fprintf(os.Stderr, "  %-40s scan-id: %s\n", f.RelPath, scanID)
			results = append(results, scanResult{File: f, ScanID: scanID})
		}

		// Collect scan IDs
		var scanIDs []string
		for _, r := range results {
			if r.ScanID != "" {
				scanIDs = append(scanIDs, r.ScanID)
			}
		}

		if len(scanIDs) == 0 {
			return fmt.Errorf("no scans were submitted successfully")
		}

		if noPoll {
			fmt.Fprintln(os.Stderr, "\nScan IDs (use 'vulnetix scan status <id> --poll' to check results):")
			for _, id := range scanIDs {
				fmt.Println(id)
			}
			return nil
		}

		// Poll for results
		fmt.Fprintf(os.Stderr, "\nPolling for results (interval: %ds)...\n", pollInterval)
		return pollScanResults(client, scanIDs, pollInterval, output)
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
			return pollScanResults(client, []string{scanID}, pollInterval, output)
		}

		result, err := client.V2ScanStatus(scanID)
		if err != nil {
			return fmt.Errorf("failed to get scan status: %w", err)
		}
		printRateLimit(client)
		return printOutput(result, output)
	},
}

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

	fmt.Fprintf(os.Stderr, "Scan submitted: %s — polling for results...\n", scanID)
	return pollScanResults(client, []string{scanID}, pollInterval, output)
}

func pollScanResults(client *vdb.Client, scanIDs []string, intervalSec int, output string) error {
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
			case "complete", "error":
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
	scanCmd.Flags().StringP("output", "o", "pretty", "Output format (json, pretty)")

	// Scan status flags
	scanStatusCmd.Flags().Bool("poll", false, "Poll until complete")
	scanStatusCmd.Flags().Int("poll-interval", 5, "Polling interval in seconds")
	scanStatusCmd.Flags().StringP("output", "o", "pretty", "Output format (json, pretty)")
}
