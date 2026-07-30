package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/binpkg"
	"github.com/vulnetix/cli/v3/internal/cdx"
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
	// A dry run makes no API calls, and this pass submits to /v2/cli.analyze.
	// Report the plan and stop.
	if dryRun, _ := cmd.Flags().GetBool("dry-run"); dryRun {
		fmt.Fprintf(os.Stderr, "[DRY RUN] binary analysis of %s skipped (it submits to /v2/cli.analyze)\n",
			nonEmptyString(scanPath, "."))
		return nil
	}
	// --list-default-rules is a listing served by the scan pipeline; the binary
	// pass has nothing to add to it.
	if list, _ := cmd.Flags().GetBool("list-default-rules"); list {
		return nil
	}
	// --no-binary-package-analysis turns off package discovery from binaries, not
	// the binary scan itself: the weakness/hash analysis and its /v2/cli.analyze
	// submission are the command's primary output and stay on.
	noPackages, _ := cmd.Flags().GetBool("no-binary-package-analysis")
	showPaths, _ := cmd.Flags().GetBool("show-introduced-paths")
	showAll, _ := cmd.Flags().GetBool("show-all-manifests")
	rootfsPaths, _ := cmd.Flags().GetStringArray("container-rootfs")
	archivePaths, _ := cmd.Flags().GetStringArray("container-archive")
	_ = showPaths
	_ = showAll

	if scanPath == "" {
		scanPath = "."
	}

	if err := runBinaryScanPath(cmd, scanPath); err != nil {
		return err
	}
	if !noPackages {
		reportBinaryPackages(scanPath, scanPath, "", scanPath)
	}
	for _, rootfs := range rootfsPaths {
		if rootfs == "" {
			continue
		}
		if pkgs := collectContainerDBPackages(rootfs, rootfs, filepath.Base(rootfs), true); len(pkgs) > 0 {
			fmt.Fprintf(os.Stderr, "Container package DB: %s contains %d installed package(s).\n", rootfs, len(pkgs))
		}
		_ = runBinaryScanPath(cmd, rootfs)
		if !noPackages {
			reportBinaryPackages(rootfs, rootfs, filepath.Base(rootfs), scanPath)
		}
	}
	for _, archive := range archivePaths {
		if archive == "" {
			continue
		}
		dir, cleanup, err := extractContainerArchive(archive)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  container archive %s: %v\n", archive, err)
			continue
		}
		if pkgs := collectContainerDBPackages(dir, dir, filepath.Base(archive), true); len(pkgs) > 0 {
			fmt.Fprintf(os.Stderr, "Container package DB: %s contains %d installed package(s).\n", archive, len(pkgs))
		}
		_ = runBinaryScanPath(cmd, dir)
		if !noPackages {
			reportBinaryPackages(dir, dir, filepath.Base(archive), scanPath)
		}
		cleanup()
	}
	return nil
}

// reportBinaryPackages discovers the packages compiled into the artefacts under
// root — Go modules, Rust crates recorded by cargo-auditable, JVM archive
// coordinates — prints them, and merges them into the repository's CycloneDX file
// so a container inventory includes dependencies no manifest declares.
//
// sbomRoot is the directory whose .vulnetix/sbom.cdx.json is updated; it is the
// scanned project, not the container root filesystem being inspected.
func reportBinaryPackages(root, labelRoot, sourceLabel, sbomRoot string) {
	owners := binpkg.OwnerIndex(nil)
	if binpkg.HasFileOwnership(root) {
		owners = binpkg.BuildOwnerIndex(root)
	}
	tree := binpkg.ScanTree(binpkg.TreeOptions{Root: root, Owners: owners})
	if len(tree.Packages) == 0 {
		if tree.Examined > 0 {
			fmt.Fprintf(os.Stderr, "Binary package analysis: %d artefact(s) examined, no embedded package metadata.\n", tree.Examined)
		}
		return
	}

	fmt.Printf("\n%s\n", bold("Packages Discovered In Binaries"))
	byEcosystem := map[string]int{}
	for _, p := range tree.Packages {
		byEcosystem[p.Ecosystem]++
	}
	for _, eco := range sortedStringKeys(byEcosystem) {
		fmt.Printf("  %-10s %d package(s)\n", eco, byEcosystem[eco])
	}
	if len(owners) > 0 {
		fmt.Printf("  %d artefact(s) not claimed by any OS package\n", len(tree.Unowned))
	}
	shown := 0
	for _, p := range tree.Packages {
		if shown >= 20 {
			fmt.Printf("  %s\n", dim(fmt.Sprintf("… %d more", len(tree.Packages)-shown)))
			break
		}
		fmt.Printf("  %-45s %-14s %s\n", truncate(p.Name, 45), truncate(p.Version, 14),
			dim(p.Method+" · "+binpkg.RelativePath(labelRoot, p.BinaryPath)))
		shown++
	}

	if err := mergeBinaryPackagesIntoBOM(tree, labelRoot, sourceLabel, sbomRoot); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not record binary packages in the SBOM: %v\n", err)
	}
}

// mergeBinaryPackagesIntoBOM folds binary-discovered packages into
// .vulnetix/sbom.cdx.json, leaving every existing component, vulnerability and
// VEX statement in place. No file is created when there is nothing on disk yet:
// `containers` is not the command that owns the SBOM.
func mergeBinaryPackagesIntoBOM(tree binpkg.TreeResult, labelRoot, sourceLabel, sbomRoot string) error {
	sbomPath := filepath.Join(sbomRoot, ".vulnetix", "sbom.cdx.json")
	existing, err := parseCDXForScan(sbomPath)
	if err != nil || existing == nil {
		return nil
	}
	incoming := &cdx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: existing.SpecVersion,
		Version:     existing.Version,
	}
	for _, p := range tree.Packages {
		purl := cdx.BuildLocalPurl(p.Name, p.Version, p.Ecosystem)
		ref := purl
		if ref == "" {
			ref = "urn:package:" + p.Ecosystem + ":" + p.Name + ":" + p.Version
		}
		artifact := binpkg.RelativePath(labelRoot, p.BinaryPath)
		locator := artifact
		if sourceLabel != "" {
			locator = sourceLabel + ":" + artifact
		}
		comp := cdx.Component{
			Type: "library", BOMRef: ref, Name: p.Name, Version: p.Version,
			Scope: "required", Purl: purl,
			Properties: []cdx.Property{
				{Name: "vulnetix:ecosystem", Value: p.Ecosystem},
				{Name: "vulnetix:scope", Value: p.Scope},
				{Name: "vulnetix:source-type", Value: scan.SourceTypeBinary},
				{Name: "vulnetix:source-file", Value: locator},
				{Name: "vulnetix:binary/discovered-in", Value: artifact},
				{Name: "vulnetix:binary/method", Value: p.Method},
			},
		}
		if p.Checksum != "" {
			comp.Properties = append(comp.Properties, cdx.Property{Name: "vulnetix:gosum-h1", Value: p.Checksum})
		}
		incoming.Components = append(incoming.Components, comp)
	}
	if len(incoming.Components) == 0 {
		return nil
	}
	merged := cdx.MergeBOMs(existing, incoming)
	return writeBOMToFile(merged, sbomPath)
}

func runBinaryScanPath(cmd *cobra.Command, scanPath string) error {
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
