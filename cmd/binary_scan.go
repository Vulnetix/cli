package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// runBinaryScan walks a container filesystem looking for ELF binaries,
// analyzes each one for weaknesses, computes hashes, looks up CIRCL
// hashlookup and MalwareBazaar, then sends results to /v2/cli.analyze.
//
// It is an internal step of the `containers` subcommand — there is no
// standalone `binary-scan` command exposed to CLI callers. It reads the
// shared scan flags (--path, --show-introduced-paths, --show-all-manifests)
// registered on the parent command via addScanFlags, and relies on the
// parent's PersistentPreRunE having already resolved vdbCreds.
func runBinaryScan(cmd *cobra.Command) error {
	scanPath, _ := cmd.Flags().GetString("path")
	showPaths, _ := cmd.Flags().GetBool("show-introduced-paths")
	showAll, _ := cmd.Flags().GetBool("show-all-manifests")
	_ = showPaths
	_ = showAll

	if scanPath == "" {
		scanPath = "."
	}

	fmt.Fprintf(os.Stderr, "Scanning %s for ELF binaries...\n", scanPath)

	// Phase 1: Walk and analyze locally.
	result := scan.ScanContainerFilesystem(scanPath)

	if result.ELFCount == 0 {
		fmt.Println("No ELF binaries found.")
		return nil
	}

	fmt.Fprintf(os.Stderr, "Found %d ELF binaries. Computing hashes and detecting weaknesses...\n", result.ELFCount)

	// Phase 2: Batch CIRCL hashlookup.
	sha1s := make([]string, 0, len(result.Binaries))
	for _, b := range result.Binaries {
		if b.Hashes.SHA1 != "" {
			sha1s = append(sha1s, b.Hashes.SHA1)
		}
	}

	var hlResults map[string]*scan.HashlookupResult
	if len(sha1s) > 0 {
		ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
		defer cancel()
		fmt.Fprintf(os.Stderr, "Looking up %d SHA-1 hashes via CIRCL hashlookup...\n", len(sha1s))
		var hlErr error
		hlResults, hlErr = scan.BulkHashlookup(ctx, sha1s)
		if hlErr != nil {
			fmt.Fprintf(os.Stderr, "  CIRCL hashlookup: %v (continuing without)\n", hlErr)
		} else {
			fmt.Fprintf(os.Stderr, "  Got %d results from CIRCL.\n", len(hlResults))
		}
	}

	// Phase 3: Attach external results.
	for i := range result.Binaries {
		b := &result.Binaries[i]
		if hlResults != nil {
			if hr, ok := hlResults[b.Hashes.SHA1]; ok {
				b.Hashlookup = hr
			}
		}
	}

	// Phase 4: Send to API.
	scannerRunUUID := uuid.NewString()
	result.SetScannerRunUUID(scannerRunUUID)

	if vdbCreds != nil {
		client := vdb.NewClientFromCredentials(vdbCreds)
		client.NoCache = true // binary scan results must always be fresh
		env := vdb.SnapshotEnv(scanPath, version, commit, buildDate)

		req := vdb.CliBinaryAnalyzeRequest{
			ScannerRunUUID: scannerRunUUID,
			Path:           result.Path,
			Binaries:       make([]vdb.CliBinaryAnalyzeEntry, 0, len(result.Binaries)),
		}
		for _, b := range result.Binaries {
			req.Binaries = append(req.Binaries, cliBinaryToEntry(b))
		}

		// Verify our own request against the embedded JSON schema before
		// sending. Non-fatal: the server re-validates, so a schema gap here
		// shouldn't drop the scan — but it surfaces contract drift early.
		if body, mErr := json.Marshal(req); mErr == nil {
			if vErr := scan.ValidateAnalyzeRequest(body); vErr != nil {
				fmt.Fprintf(os.Stderr, "  request schema check: %v (sending anyway)\n", vErr)
			}
		}

		fmt.Fprintf(os.Stderr, "Sending %d binaries to /v2/cli.analyze...\n", len(req.Binaries))
		resp, err := client.CliBinaryAnalyze(env, req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "API error: %v (results available locally)\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "API: %d binaries stored, %d findings created (%d malware, %d CVE matches)\n",
				resp.Data.BinariesStored, resp.Data.FindingsCreated,
				resp.Data.MalwareHits, resp.Data.CveMatches)
		}
	} else {
		fmt.Fprintf(os.Stderr, "No credentials — skipping API submission.\n")
	}

	// Phase 5: Print local results.
	printBinaryScanResults(result)

	return nil
}

// cliBinaryToEntry converts a local BinaryResult to the API wire type.
func cliBinaryToEntry(b scan.BinaryResult) vdb.CliBinaryAnalyzeEntry {
	e := vdb.CliBinaryAnalyzeEntry{
		Path:         b.Path,
		Size:         b.Size,
		ELFType:      b.ELFType,
		ELFArch:      b.ELFArch,
		ELFOSABI:     b.ELFOSABI,
		Weaknesses:   b.Weaknesses,
		Capabilities: b.Capabilities,
		Strings:      b.Strings,
		Exif:         b.Exif,
		Hashes: vdb.CliBinaryHashes{
			SHA256:    b.Hashes.SHA256,
			MD5:       b.Hashes.MD5,
			SHA1:      b.Hashes.SHA1,
			SSDEEP:    b.Hashes.SSDEEP,
			TLSH:      b.Hashes.TLSH,
			SHA256Raw: b.Hashes.SHA256Raw,
			MD5Raw:    b.Hashes.MD5Raw,
			SHA1Raw:   b.Hashes.SHA1Raw,
		},
	}
	if b.Hashlookup != nil {
		e.Hashlookup = &vdb.CliHashlookupResult{
			FileName:       b.Hashlookup.FileName,
			FileSize:       b.Hashlookup.FileSize,
			MD5:            b.Hashlookup.MD5,
			SHA1:           b.Hashlookup.SHA1,
			SHA256:         b.Hashlookup.SHA256,
			SSDEEP:         b.Hashlookup.SSDEEP,
			TLSH:           b.Hashlookup.TLSH,
			PackageName:    b.Hashlookup.PackageName,
			PackageVersion: b.Hashlookup.PackageVersion,
		}
	}
	if b.MalwareBazaar != nil {
		e.MalwareBazaar = &vdb.CliMalwareBazaarResult{
			Malicious: b.MalwareBazaar.Malicious,
			FileName:  b.MalwareBazaar.FileName,
		}
	}
	return e
}

func printBinaryScanResults(result *scan.ScanResult) {
	fmt.Printf("\n%s\n", bold("Binary Scan Results"))
	fmt.Printf("  Path:         %s\n", result.Path)
	fmt.Printf("  Total files:  %d\n", result.Total)
	fmt.Printf("  ELF binaries: %d\n", result.ELFCount)

	if len(result.Errors) > 0 {
		fmt.Printf("  Errors:       %d\n", len(result.Errors))
	}

	if len(result.Binaries) == 0 {
		return
	}

	// Summary counts.
	var setuidCount, noPIE, noRELRO, noCanary int
	for _, b := range result.Binaries {
		for _, w := range b.Weaknesses {
			switch w {
			case "setuid":
				setuidCount++
			case "no-pie":
				noPIE++
			case "no-relro", "partial-relro":
				noRELRO++
			case "no-stack-canary":
				noCanary++
			}
		}
	}

	fmt.Printf("\n%s\n", bold("Weakness Summary"))
	if setuidCount > 0 {
		fmt.Printf("  %s binaries with setuid:     %d\n", redText(fmt.Sprintf("%d", setuidCount)), setuidCount)
	}
	fmt.Printf("  No PIE:                      %d\n", noPIE)
	fmt.Printf("  No/partial RELRO:            %d\n", noRELRO)
	fmt.Printf("  No stack canary:             %d\n", noCanary)
	fmt.Printf("  World-writable:              %d\n", countWeakness(result, "world-writable"))
	fmt.Printf("  NX disabled:                 %d\n", countWeakness(result, "nx-disabled"))
	fmt.Printf("  Setgid:                      %d\n", countWeakness(result, "setgid"))

	// Detailed table.
	fmt.Printf("\n%s\n", bold("Binary Details"))
	fmt.Println("  " + dim("PATH                                                 TYPE     ARCH         WEAKNESSES"))
	for _, b := range result.Binaries {
		weaknesses := stringsJoin(b.Weaknesses, ",")
		if weaknesses == "" {
			weaknesses = "-"
		}
		fmt.Printf("  %-52s %-8s %-12s %s\n",
			truncate(b.Path, 52),
			b.ELFType,
			b.ELFArch,
			dim(weaknesses),
		)
		if b.Hashlookup != nil && b.Hashlookup.PackageName != "" {
			pkg := b.Hashlookup.PackageName
			if b.Hashlookup.PackageVersion != "" {
				pkg += "@" + b.Hashlookup.PackageVersion
			}
			fmt.Printf("    ↳ %s\n", greenText("package: "+pkg))
		}
	}

	if len(result.Errors) > 0 {
		fmt.Printf("\n%s\n", bold("Errors"))
		for _, e := range result.Errors {
			fmt.Printf("  %s\n", dim(e))
		}
	}
}

func countWeakness(result *scan.ScanResult, name string) int {
	n := 0
	for _, b := range result.Binaries {
		for _, w := range b.Weaknesses {
			if w == name {
				n++
			}
		}
	}
	return n
}

// Simple terminal formatting helpers (avoiding external deps for now).
func bold(s string) string      { return "\033[1m" + s + "\033[0m" }
func dim(s string) string       { return "\033[2m" + s + "\033[0m" }
func redText(s string) string   { return "\033[31m" + s + "\033[0m" }
func greenText(s string) string { return "\033[32m" + s + "\033[0m" }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func stringsJoin(ss []string, sep string) string {
	if ss == nil {
		return ""
	}
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}
