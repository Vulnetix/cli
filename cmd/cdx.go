package cmd

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/aibom"
	"github.com/vulnetix/cli/v3/internal/cbom"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/ecosystems"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/scan"
)

var cdxCmd = &cobra.Command{
	Use:   "cdx [path]",
	Short: "Generate a standalone CycloneDX SBOM without VDB lookup or upload",
	Long: `Generate one local CycloneDX document containing the package SBOM, AI Bill
of Materials (AIBOM), and Cryptography Bill of Materials (CBOM).

The command is offline: it reads local manifests, installed package directories,
container root filesystems/archives, CI/CD files, shell scripts, binaries and
signature sidecars, then writes a CycloneDX JSON file. It does not query the
Vulnetix VDB, upload data, update memory.yaml, enforce quality gates or contact
a container daemon.

Examples:
  vulnetix cdx
  vulnetix cdx ./service -o cyclonedx-json
  vulnetix cdx --container-rootfs ./rootfs
  vulnetix cdx --container-archive ./image.tar
  vulnetix cdx --no-aibom --no-cbom --output-file build/sbom.cdx.json`,
	Args:         cobra.MaximumNArgs(1),
	RunE:         runCDX,
	SilenceUsage: true,
}

type cdxRunOptions struct {
	RootPath          string
	Depth             int
	Exclude           []string
	Ignore            []string
	Output            string
	OutputFile        string
	SpecVersion       string
	NoManifests       bool
	NoFilesystem      bool
	NoContainerfiles  bool
	NoCI              bool
	NoShell           bool
	NoBinaryAnalysis  bool
	NoAIBOM           bool
	NoCBOM            bool
	NoSignatures      bool
	IncludeHome       bool
	IncludeIgnored    bool
	ContainerRootfs   []string
	ContainerArchives []string
	AIBOMCatalog      string
	CBOMCatalog       string
	NoBuiltinAIBOM    bool
	NoBuiltinCBOM     bool
}

type cdxSummary struct {
	OutputFile        string         `json:"outputFile"`
	PackageCount      int            `json:"packageCount"`
	SourceCounts      map[string]int `json:"sourceCounts"`
	ManifestFileCount int            `json:"manifestFileCount"`
	BinaryCount       int            `json:"binaryCount"`
	AITools           int            `json:"aiTools"`
	AILibraries       int            `json:"aiLibraries"`
	AIModels          int            `json:"aiModels"`
	CryptoAssets      int            `json:"cryptoAssets"`
	CryptoLibraries   int            `json:"cryptoLibraries"`
	CryptoCerts       int            `json:"cryptoCertificates"`
	Warnings          []string       `json:"warnings,omitempty"`
}

func init() {
	cdxCmd.Flags().String("path", ".", "Directory to scan")
	cdxCmd.Flags().Int("depth", 25, "Maximum recursion depth for file discovery")
	cdxCmd.Flags().StringArray("exclude", nil, "Exclude paths matching glob pattern during manifest discovery (repeatable)")
	cdxCmd.Flags().StringArray("ignore", nil, "Exclude paths matching glob pattern during local inventory discovery (repeatable)")
	cdxCmd.Flags().StringP("output", "o", "pretty", "Terminal output format: pretty, json, cyclonedx-json")
	cdxCmd.Flags().String("output-file", "", "Path to write the CycloneDX SBOM (default: <path>/.vulnetix/sbom.cdx.json)")
	cdxCmd.Flags().String("spec-version", "1.7", "CycloneDX spec version: 1.6 or 1.7")
	cdxCmd.Flags().Bool("no-manifests", false, "Skip package manifest and lockfile parsing")
	cdxCmd.Flags().Bool("no-filesystem", false, "Skip installed-package filesystem discovery")
	cdxCmd.Flags().Bool("no-containerfiles", false, "Skip Dockerfile, compose, Kubernetes and Helm package discovery")
	cdxCmd.Flags().Bool("no-ci", false, "Skip CI/CD pipeline file package discovery")
	cdxCmd.Flags().Bool("no-shell", false, "Skip shell-script package discovery")
	cdxCmd.Flags().Bool("no-binary-analysis", false, "Skip local ELF binary analysis")
	cdxCmd.Flags().Bool("no-aibom", false, "Skip AIBOM detection and omit AI components")
	cdxCmd.Flags().Bool("no-cbom", false, "Skip CBOM detection and omit cryptographic components")
	cdxCmd.Flags().Bool("no-signatures", false, "Skip local signature, attestation and transparency-log sidecar discovery")
	cdxCmd.Flags().Bool("include-home", false, "Also inspect user-scoped package caches for installed packages")
	cdxCmd.Flags().Bool("cdx-include-ignored", false, "Include files matched by .gitignore (default: gitignored paths are skipped)")
	cdxCmd.Flags().StringArray("container-rootfs", nil, "Container root filesystem directory to inspect for OS packages and binaries (repeatable)")
	cdxCmd.Flags().StringArray("container-archive", nil, "Docker/OCI/rootfs tar archive to inspect for OS packages and binaries (repeatable)")
	cdxCmd.Flags().String("aibom-catalog", "", "Path to an AIBOM catalog file to merge over (or replace) the builtin catalog")
	cdxCmd.Flags().String("cbom-catalog", "", "Path to a CBOM catalog file to merge over (or replace) the builtin catalog")
	cdxCmd.Flags().Bool("no-builtin-aibom-catalog", false, "Do not load the embedded AIBOM catalog (use only --aibom-catalog)")
	cdxCmd.Flags().Bool("no-builtin-cbom-catalog", false, "Do not load the embedded CBOM catalog (use only --cbom-catalog)")
	_ = cdxCmd.MarkFlagDirname("path")
	rootCmd.AddCommand(cdxCmd)
}

func runCDX(cmd *cobra.Command, args []string) error {
	opts, err := readCDXOptions(cmd, args)
	if err != nil {
		return err
	}
	gitCtx := gitctx.Collect(opts.RootPath)
	sysInfo := gitctx.CollectSystemInfo()

	packages, manifestCount, binaryCount, warnings := collectCDXPackages(opts)
	var aiDet *cyclonedx.AIDetections
	var cryptoDet *cyclonedx.CryptoDetections
	if !opts.NoAIBOM {
		det, err := detectCDXAIBOM(opts)
		if err != nil {
			warnings = append(warnings, "aibom: "+err.Error())
		} else {
			aiDet = &det
		}
	}
	if !opts.NoCBOM {
		det, err := detectCDXCBOM(opts)
		if err != nil {
			warnings = append(warnings, "cbom: "+err.Error())
		} else {
			cryptoDet = &det
		}
	}

	bomData, err := cyclonedx.BuildSBOM(cyclonedx.SBOMInventory{
		Packages:         packages,
		AIDetections:     aiDet,
		CryptoDetections: cryptoDet,
	}, cyclonedx.SBOMOptions{
		SpecVersion: opts.SpecVersion,
		ToolName:    "vulnetix-cdx",
		ToolVersion: version,
		Project:     aibomProject(gitCtx, sysInfo),
	})
	if err != nil {
		return err
	}

	if err := writeCDXFile(opts.OutputFile, bomData); err != nil {
		return err
	}
	summary := cdxSummary{
		OutputFile:        opts.OutputFile,
		PackageCount:      len(packages),
		SourceCounts:      countCDXSources(packages),
		ManifestFileCount: manifestCount,
		BinaryCount:       binaryCount,
		Warnings:          warnings,
	}
	if aiDet != nil {
		summary.AITools = len(aiDet.Tools)
		summary.AILibraries = len(aiDet.Libraries)
		summary.AIModels = len(aiDet.Models)
	}
	if cryptoDet != nil {
		summary.CryptoAssets = len(cryptoDet.Assets)
		summary.CryptoLibraries = len(cryptoDet.Libraries)
		summary.CryptoCerts = len(cryptoDet.Certificates)
	}

	switch opts.Output {
	case "json":
		data, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, string(data))
	case "cyclonedx-json":
		fmt.Fprintln(os.Stdout, string(bomData))
	default:
		renderCDXSummary(cmd, summary)
	}
	return nil
}

func readCDXOptions(cmd *cobra.Command, args []string) (cdxRunOptions, error) {
	rootPath, _ := cmd.Flags().GetString("path")
	if len(args) == 1 && args[0] != "" {
		rootPath = args[0]
	}
	if rootPath == "" {
		rootPath = "."
	}
	abs, err := filepath.Abs(rootPath)
	if err != nil {
		return cdxRunOptions{}, err
	}
	depth, _ := cmd.Flags().GetInt("depth")
	exclude, _ := cmd.Flags().GetStringArray("exclude")
	ignore, _ := cmd.Flags().GetStringArray("ignore")
	output, _ := cmd.Flags().GetString("output")
	outputFile, _ := cmd.Flags().GetString("output-file")
	specVersion, _ := cmd.Flags().GetString("spec-version")
	switch output {
	case "pretty", "table", "json", "cyclonedx-json":
	default:
		return cdxRunOptions{}, fmt.Errorf("--output must be one of: pretty, json, cyclonedx-json")
	}
	switch specVersion {
	case "1.6", "1.7":
	default:
		return cdxRunOptions{}, fmt.Errorf("--spec-version must be one of: 1.6, 1.7")
	}
	if outputFile == "" {
		outputFile = filepath.Join(abs, ".vulnetix", "sbom.cdx.json")
	}
	warnOutputExtension(outputFile, ".cdx.json")
	noManifests, _ := cmd.Flags().GetBool("no-manifests")
	noFilesystem, _ := cmd.Flags().GetBool("no-filesystem")
	noContainerfiles, _ := cmd.Flags().GetBool("no-containerfiles")
	noCI, _ := cmd.Flags().GetBool("no-ci")
	noShell, _ := cmd.Flags().GetBool("no-shell")
	noBinary, _ := cmd.Flags().GetBool("no-binary-analysis")
	noAIBOM, _ := cmd.Flags().GetBool("no-aibom")
	noCBOM, _ := cmd.Flags().GetBool("no-cbom")
	noSignatures, _ := cmd.Flags().GetBool("no-signatures")
	includeHome, _ := cmd.Flags().GetBool("include-home")
	includeIgnored, _ := cmd.Flags().GetBool("cdx-include-ignored")
	rootfs, _ := cmd.Flags().GetStringArray("container-rootfs")
	archives, _ := cmd.Flags().GetStringArray("container-archive")
	aibomCatalog, _ := cmd.Flags().GetString("aibom-catalog")
	cbomCatalog, _ := cmd.Flags().GetString("cbom-catalog")
	noBuiltinAIBOM, _ := cmd.Flags().GetBool("no-builtin-aibom-catalog")
	noBuiltinCBOM, _ := cmd.Flags().GetBool("no-builtin-cbom-catalog")
	return cdxRunOptions{
		RootPath: abs, Depth: depth, Exclude: exclude, Ignore: ignore, Output: output, OutputFile: outputFile, SpecVersion: specVersion,
		NoManifests: noManifests, NoFilesystem: noFilesystem, NoContainerfiles: noContainerfiles, NoCI: noCI, NoShell: noShell,
		NoBinaryAnalysis: noBinary, NoAIBOM: noAIBOM, NoCBOM: noCBOM, NoSignatures: noSignatures, IncludeHome: includeHome,
		IncludeIgnored: includeIgnored, ContainerRootfs: rootfs, ContainerArchives: archives,
		AIBOMCatalog: aibomCatalog, CBOMCatalog: cbomCatalog, NoBuiltinAIBOM: noBuiltinAIBOM, NoBuiltinCBOM: noBuiltinCBOM,
	}, nil
}

func collectCDXPackages(opts cdxRunOptions) ([]cyclonedx.SBOMPackage, int, int, []string) {
	var packages []cyclonedx.SBOMPackage
	var warnings []string
	manifestCount := 0
	if !opts.NoManifests || !opts.NoContainerfiles || !opts.NoCI || !opts.NoShell {
		files, err := scan.WalkForScanFiles(scan.WalkOptions{
			RootPath: opts.RootPath, MaxDepth: opts.Depth,
			Excludes:         append(append([]string{}, opts.Exclude...), opts.Ignore...),
			RespectGitignore: !opts.IncludeIgnored,
		})
		if err != nil {
			warnings = append(warnings, "manifest discovery: "+err.Error())
		}
		for _, f := range files {
			if !includeCDXDetectedFile(f, opts) {
				continue
			}
			manifestCount++
			pkgs, err := scan.ParseManifestWithScope(f.Path, f.ManifestInfo.Type)
			if err != nil {
				warnings = append(warnings, f.RelPath+": "+err.Error())
				continue
			}
			if !opts.NoFilesystem {
				if resolved, drop, gerr := scan.ApplyBuildOrLockGate(
					f.ManifestInfo.Ecosystem, f.ManifestInfo.Type, f.Path, f.RelPath,
					f.ManifestInfo.Confidence != scan.ConfidenceTentative, pkgs,
				); gerr == nil && !drop {
					pkgs = resolved
				}
			}
			for _, p := range pkgs {
				p.SourceFile = f.RelPath
				if p.Scope == "" {
					p.Scope = scan.ScopeProduction
				}
				if p.SourceType == "" {
					if f.ManifestInfo.Language == "ci" || f.ManifestInfo.Language == "shell" {
						p.SourceType = scan.SourceTypeCommand
					} else {
						p.SourceType = scan.SourceTypeManifest
					}
				}
				packages = append(packages, cdxPackageFromScan(p, opts.RootPath, !opts.NoSignatures))
			}
		}
	}
	if !opts.NoFilesystem {
		packages = append(packages, collectInstalledPackages(opts)...)
	}

	binaryCount := 0
	if !opts.NoBinaryAnalysis {
		binPkgs, count := collectBinaryPackages(opts.RootPath, opts.RootPath, !opts.NoSignatures)
		binaryCount += count
		packages = append(packages, binPkgs...)
	}
	for _, rootfs := range opts.ContainerRootfs {
		abs, err := filepath.Abs(rootfs)
		if err != nil {
			warnings = append(warnings, rootfs+": "+err.Error())
			continue
		}
		packages = append(packages, collectContainerDBPackages(abs, abs, filepath.Base(abs), !opts.NoSignatures)...)
		if !opts.NoFilesystem {
			packages = append(packages, collectInstalledPackages(cdxRunOptions{RootPath: abs, IncludeHome: false, NoSignatures: opts.NoSignatures})...)
		}
		if !opts.NoBinaryAnalysis {
			binPkgs, count := collectBinaryPackages(abs, abs, !opts.NoSignatures)
			binaryCount += count
			packages = append(packages, binPkgs...)
		}
	}
	for _, archive := range opts.ContainerArchives {
		dir, cleanup, err := extractContainerArchive(archive)
		if err != nil {
			warnings = append(warnings, archive+": "+err.Error())
			continue
		}
		packages = append(packages, collectContainerDBPackages(dir, dir, filepath.Base(archive), !opts.NoSignatures)...)
		if !opts.NoFilesystem {
			packages = append(packages, collectInstalledPackages(cdxRunOptions{RootPath: dir, IncludeHome: false, NoSignatures: opts.NoSignatures})...)
		}
		if !opts.NoBinaryAnalysis {
			binPkgs, count := collectBinaryPackages(dir, dir, !opts.NoSignatures)
			binaryCount += count
			packages = append(packages, binPkgs...)
		}
		cleanup()
	}
	return dedupeCDXPackages(packages), manifestCount, binaryCount, warnings
}

func includeCDXDetectedFile(f scan.DetectedFile, opts cdxRunOptions) bool {
	if f.FileType != scan.FileTypeManifest || f.ManifestInfo == nil || !f.Supported {
		return false
	}
	lang := f.ManifestInfo.Language
	switch {
	case lang == "registry-config":
		return false
	case lang == "docker" || lang == "kubernetes" || lang == "helm":
		return !opts.NoContainerfiles
	case lang == "ci":
		return !opts.NoCI
	case lang == "shell":
		return !opts.NoShell
	default:
		return !opts.NoManifests
	}
}

func cdxPackageFromScan(p scan.ScopedPackage, root string, includeSignatures bool) cyclonedx.SBOMPackage {
	out := cyclonedx.SBOMPackage{
		Name: p.Name, Version: p.Version, VersionSpec: p.VersionSpec, Ecosystem: p.Ecosystem,
		Scope: p.Scope, Purl: cyclonedx.SBOMPurl(p.Name, p.Version, p.Ecosystem),
		SourceFile: p.SourceFile, SourceType: p.SourceType, InstalledPath: p.InstalledPath,
		IsDirect: p.IsDirect, RegistryType: p.RegistryType, IsPrivateRegistry: p.IsPrivateRegistry,
	}
	for _, h := range p.Checksums {
		out.Hashes = append(out.Hashes, cyclonedx.SBOMHash{Alg: h.Alg, Content: h.Value})
	}
	out.Evidence = []cyclonedx.SBOMEvidence{{Method: nonEmptyString(p.SourceType, "manifest"), Locator: p.SourceFile, Confidence: "high"}}
	if includeSignatures && p.SourceFile != "" {
		out.Signatures = discoverSignaturesForFile(root, p.SourceFile)
	}
	return out
}

func collectInstalledPackages(opts cdxRunOptions) []cyclonedx.SBOMPackage {
	targets := ecosystems.Resolve(opts.RootPath, opts.IncludeHome)
	var out []cyclonedx.SBOMPackage
	for _, t := range targets {
		switch t.EngineSlug {
		case "npm":
			out = append(out, collectNpmInstalled(t.Path, opts.RootPath, !opts.NoSignatures)...)
		case "pypi":
			out = append(out, collectPythonInstalled(t.Path, opts.RootPath, !opts.NoSignatures)...)
		case "go":
			out = append(out, collectGoInstalled(t.Path, opts.RootPath, !opts.NoSignatures)...)
		case "rubygems":
			out = append(out, collectRubyInstalled(t.Path, opts.RootPath, !opts.NoSignatures)...)
		case "nuget":
			out = append(out, collectNugetInstalled(t.Path, opts.RootPath, !opts.NoSignatures)...)
		default:
			if strings.EqualFold(t.Ecosystem, "php") {
				out = append(out, collectComposerInstalled(t.Path, opts.RootPath, !opts.NoSignatures)...)
			}
		}
	}
	return out
}

func collectNpmInstalled(dir, root string, includeSignatures bool) []cyclonedx.SBOMPackage {
	var out []cyclonedx.SBOMPackage
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "package.json" {
			return nil
		}
		var doc struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			License any    `json:"license"`
		}
		if data, err := os.ReadFile(path); err == nil && json.Unmarshal(data, &doc) == nil && doc.Name != "" {
			rel := relTo(root, path)
			pkg := cyclonedx.SBOMPackage{
				Name: doc.Name, Version: doc.Version, Ecosystem: "npm", Scope: scan.ScopeProduction,
				SourceFile: rel, SourceType: scan.SourceTypeInstalled, InstalledPath: relTo(root, filepath.Dir(path)),
				IsDirect: false, Licenses: licenseValues(doc.License),
				Evidence: []cyclonedx.SBOMEvidence{{Method: scan.SourceTypeInstalled, Locator: rel, Confidence: "high"}},
			}
			if includeSignatures {
				pkg.Signatures = discoverSignaturesForFile(root, rel)
			}
			out = append(out, pkg)
		}
		return nil
	})
	return out
}

func collectPythonInstalled(dir, root string, includeSignatures bool) []cyclonedx.SBOMPackage {
	var out []cyclonedx.SBOMPackage
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".dist-info") && !strings.HasSuffix(name, ".egg-info") {
			return nil
		}
		distName, version := splitPythonDistInfo(strings.TrimSuffix(strings.TrimSuffix(name, ".dist-info"), ".egg-info"))
		rel := relTo(root, path)
		lic := metadataLicense(filepath.Join(path, "METADATA"))
		pkg := cyclonedx.SBOMPackage{
			Name: distName, Version: version, Ecosystem: "pypi", Scope: scan.ScopeProduction,
			SourceFile: rel, SourceType: scan.SourceTypeInstalled, InstalledPath: rel, Licenses: lic,
			Evidence: []cyclonedx.SBOMEvidence{{Method: scan.SourceTypeInstalled, Locator: rel, Confidence: "high"}},
		}
		if includeSignatures {
			pkg.Signatures = discoverSignaturesForFile(root, rel)
		}
		out = append(out, pkg)
		return filepath.SkipDir
	})
	return out
}

func collectGoInstalled(dir, root string, includeSignatures bool) []cyclonedx.SBOMPackage {
	var out []cyclonedx.SBOMPackage
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() || !strings.Contains(d.Name(), "@") {
			return nil
		}
		rel := relTo(root, path)
		name, ver := splitAtLast(d.Name(), "@")
		if name == "" || ver == "" {
			return nil
		}
		pkg := cyclonedx.SBOMPackage{
			Name: name, Version: strings.TrimPrefix(ver, "v"), Ecosystem: "golang", Scope: scan.ScopeProduction,
			SourceFile: rel, SourceType: scan.SourceTypeInstalled, InstalledPath: rel,
			Evidence: []cyclonedx.SBOMEvidence{{Method: scan.SourceTypeInstalled, Locator: rel, Confidence: "medium"}},
		}
		if includeSignatures {
			pkg.Signatures = discoverSignaturesForFile(root, rel)
		}
		out = append(out, pkg)
		return filepath.SkipDir
	})
	return out
}

func collectRubyInstalled(dir, root string, includeSignatures bool) []cyclonedx.SBOMPackage {
	var out []cyclonedx.SBOMPackage
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() || filepath.Base(filepath.Dir(path)) != "gems" {
			return nil
		}
		name, ver := splitNameVersionDir(d.Name())
		if name == "" {
			return nil
		}
		rel := relTo(root, path)
		pkg := cyclonedx.SBOMPackage{
			Name: name, Version: ver, Ecosystem: "gem", Scope: scan.ScopeProduction,
			SourceFile: rel, SourceType: scan.SourceTypeInstalled, InstalledPath: rel,
			Evidence: []cyclonedx.SBOMEvidence{{Method: scan.SourceTypeInstalled, Locator: rel, Confidence: "medium"}},
		}
		if includeSignatures {
			pkg.Signatures = discoverSignaturesForFile(root, rel)
		}
		out = append(out, pkg)
		return filepath.SkipDir
	})
	return out
}

func collectComposerInstalled(dir, root string, _ bool) []cyclonedx.SBOMPackage {
	installed := filepath.Join(dir, "composer", "installed.json")
	data, err := os.ReadFile(installed)
	if err != nil {
		return nil
	}
	var doc struct {
		Packages []struct {
			Name    string   `json:"name"`
			Version string   `json:"version"`
			License []string `json:"license"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		var list []struct {
			Name    string   `json:"name"`
			Version string   `json:"version"`
			License []string `json:"license"`
		}
		if err := json.Unmarshal(data, &list); err != nil {
			return nil
		}
		doc.Packages = list
	}
	var out []cyclonedx.SBOMPackage
	for _, p := range doc.Packages {
		rel := relTo(root, installed)
		out = append(out, cyclonedx.SBOMPackage{
			Name: p.Name, Version: cleanInstalledVersion(p.Version), Ecosystem: "composer", Scope: scan.ScopeProduction,
			SourceFile: rel, SourceType: scan.SourceTypeInstalled, InstalledPath: relTo(root, filepath.Join(dir, p.Name)),
			Licenses: p.License, Evidence: []cyclonedx.SBOMEvidence{{Method: scan.SourceTypeInstalled, Locator: rel, Confidence: "high"}},
		})
	}
	return out
}

func collectNugetInstalled(dir, root string, includeSignatures bool) []cyclonedx.SBOMPackage {
	var out []cyclonedx.SBOMPackage
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".nuspec") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var spec struct {
			Metadata struct {
				ID      string `xml:"id"`
				Version string `xml:"version"`
				License struct {
					Text string `xml:",chardata"`
				} `xml:"license"`
			} `xml:"metadata"`
		}
		if xml.Unmarshal(data, &spec) != nil || spec.Metadata.ID == "" {
			return nil
		}
		rel := relTo(root, path)
		pkg := cyclonedx.SBOMPackage{
			Name: spec.Metadata.ID, Version: spec.Metadata.Version, Ecosystem: "nuget", Scope: scan.ScopeProduction,
			SourceFile: rel, SourceType: scan.SourceTypeInstalled, InstalledPath: relTo(root, filepath.Dir(path)),
			Licenses: strings.Fields(spec.Metadata.License.Text),
			Evidence: []cyclonedx.SBOMEvidence{{Method: scan.SourceTypeInstalled, Locator: rel, Confidence: "high"}},
		}
		if includeSignatures {
			pkg.Signatures = discoverSignaturesForFile(root, rel)
		}
		out = append(out, pkg)
		return nil
	})
	return out
}

func collectContainerDBPackages(root, labelRoot, sourceLabel string, includeSignatures bool) []cyclonedx.SBOMPackage {
	var out []cyclonedx.SBOMPackage
	for _, p := range []string{"var/lib/dpkg/status", "lib/apk/db/installed", "var/lib/apk/db/installed"} {
		full := filepath.Join(root, filepath.FromSlash(p))
		data, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		rel := sourceLabel + ":" + filepath.ToSlash(p)
		if strings.Contains(p, "dpkg") {
			out = append(out, parseDpkgStatus(data, rel, labelRoot, includeSignatures)...)
		} else {
			out = append(out, parseAPKInstalled(data, rel, labelRoot, includeSignatures)...)
		}
	}
	matches, _ := filepath.Glob(filepath.Join(root, "var/lib/pacman/local/*/desc"))
	for _, m := range matches {
		if data, err := os.ReadFile(m); err == nil {
			out = append(out, parsePacmanDesc(data, sourceLabel+":"+relTo(root, m), labelRoot, includeSignatures)...)
		}
	}
	return out
}

func parseDpkgStatus(data []byte, rel, root string, includeSignatures bool) []cyclonedx.SBOMPackage {
	var out []cyclonedx.SBOMPackage
	for _, block := range strings.Split(string(data), "\n\n") {
		fields := fieldBlock(block)
		if fields["Package"] == "" {
			continue
		}
		pkg := cyclonedx.SBOMPackage{
			Name: fields["Package"], Version: fields["Version"], Ecosystem: "deb", Scope: scan.ScopeProduction,
			SourceFile: rel, SourceType: scan.SourceTypeContainer, Evidence: []cyclonedx.SBOMEvidence{{Method: scan.SourceTypeContainer, Locator: rel, Confidence: "high"}},
		}
		if includeSignatures {
			pkg.Signatures = discoverSignaturesForFile(root, rel)
		}
		out = append(out, pkg)
	}
	return out
}

func parseAPKInstalled(data []byte, rel, root string, includeSignatures bool) []cyclonedx.SBOMPackage {
	var out []cyclonedx.SBOMPackage
	for _, block := range strings.Split(string(data), "\n\n") {
		var name, version string
		for _, line := range strings.Split(block, "\n") {
			switch {
			case strings.HasPrefix(line, "P:"):
				name = strings.TrimSpace(strings.TrimPrefix(line, "P:"))
			case strings.HasPrefix(line, "V:"):
				version = strings.TrimSpace(strings.TrimPrefix(line, "V:"))
			}
		}
		if name == "" {
			continue
		}
		pkg := cyclonedx.SBOMPackage{
			Name: name, Version: version, Ecosystem: "apk", Scope: scan.ScopeProduction,
			SourceFile: rel, SourceType: scan.SourceTypeContainer, Evidence: []cyclonedx.SBOMEvidence{{Method: scan.SourceTypeContainer, Locator: rel, Confidence: "high"}},
		}
		if includeSignatures {
			pkg.Signatures = discoverSignaturesForFile(root, rel)
		}
		out = append(out, pkg)
	}
	return out
}

func parsePacmanDesc(data []byte, rel, root string, includeSignatures bool) []cyclonedx.SBOMPackage {
	var name, version string
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		switch line {
		case "%NAME%":
			if i+1 < len(lines) {
				name = strings.TrimSpace(lines[i+1])
			}
		case "%VERSION%":
			if i+1 < len(lines) {
				version = strings.TrimSpace(lines[i+1])
			}
		}
	}
	if name == "" {
		return nil
	}
	pkg := cyclonedx.SBOMPackage{
		Name: name, Version: version, Ecosystem: "arch", Scope: scan.ScopeProduction,
		SourceFile: rel, SourceType: scan.SourceTypeContainer, Evidence: []cyclonedx.SBOMEvidence{{Method: scan.SourceTypeContainer, Locator: rel, Confidence: "high"}},
	}
	if includeSignatures {
		pkg.Signatures = discoverSignaturesForFile(root, rel)
	}
	return []cyclonedx.SBOMPackage{pkg}
}

func collectBinaryPackages(root, labelRoot string, includeSignatures bool) ([]cyclonedx.SBOMPackage, int) {
	result := scan.ScanContainerFilesystem(root)
	var out []cyclonedx.SBOMPackage
	for _, b := range result.Binaries {
		rel := relTo(labelRoot, b.Path)
		pkg := cyclonedx.SBOMPackage{
			Type: "file", Name: filepath.Base(b.Path), Ecosystem: "binary", SourceFile: rel,
			SourceType: scan.SourceTypeBinary, InstalledPath: rel,
			Hashes: []cyclonedx.SBOMHash{
				{Alg: "SHA-256", Content: b.Hashes.SHA256},
				{Alg: "SHA-1", Content: b.Hashes.SHA1},
				{Alg: "MD5", Content: b.Hashes.MD5},
				{Alg: "SSDEEP", Content: b.Hashes.SSDEEP},
				{Alg: "TLSH", Content: b.Hashes.TLSH},
			},
			Evidence: []cyclonedx.SBOMEvidence{{
				Method: "binary", Locator: rel,
				Detail:     strings.Join(append(append([]string{}, b.Weaknesses...), b.Capabilities...), ","),
				Confidence: "high",
			}},
		}
		if includeSignatures {
			pkg.Signatures = discoverSignaturesForFile(labelRoot, rel)
		}
		out = append(out, pkg)
	}
	return out, result.ELFCount
}

func detectCDXAIBOM(opts cdxRunOptions) (cyclonedx.AIDetections, error) {
	cat, err := aibom.LoadCatalog(opts.AIBOMCatalog, opts.NoBuiltinAIBOM)
	if err != nil {
		return cyclonedx.AIDetections{}, err
	}
	compiled, err := cat.Compile()
	if err != nil {
		return cyclonedx.AIDetections{}, fmt.Errorf("invalid AIBOM catalog: %w", err)
	}
	return aibom.Detect(aibom.Options{
		Root: opts.RootPath, MaxDepth: opts.Depth, Ignore: opts.Ignore,
		ScanEnv: true, IncludeHome: opts.IncludeHome, ScanSource: true, ScanCommits: true, ScanIaC: !opts.NoContainerfiles,
		CommitMax: 2000, Catalog: compiled, RespectGitignore: !opts.IncludeIgnored,
	})
}

func detectCDXCBOM(opts cdxRunOptions) (cyclonedx.CryptoDetections, error) {
	cat, err := cbom.LoadCatalog(opts.CBOMCatalog, opts.NoBuiltinCBOM)
	if err != nil {
		return cyclonedx.CryptoDetections{}, err
	}
	compiled, err := cat.Compile()
	if err != nil {
		return cyclonedx.CryptoDetections{}, fmt.Errorf("invalid CBOM catalog: %w", err)
	}
	return cbom.Detect(cbom.Options{
		Root: opts.RootPath, MaxDepth: opts.Depth, Ignore: opts.Ignore,
		ScanSource: true, ScanConfig: true, ScanCerts: true, ScanDeps: true,
		Catalog: compiled, RespectGitignore: !opts.IncludeIgnored,
	})
}

func discoverSignaturesForFile(root, rel string) []cyclonedx.SBOMSignature {
	if rel == "" {
		return nil
	}
	full := filepath.Join(root, filepath.FromSlash(strings.SplitN(rel, ":", 2)[0]))
	if strings.Contains(rel, ":") {
		return nil
	}
	var out []cyclonedx.SBOMSignature
	for _, path := range signatureCandidates(full) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(data)
		sig := cyclonedx.SBOMSignature{
			Algorithm:  signatureAlgorithm(path),
			Value:      "sha256:" + hex.EncodeToString(sum[:]),
			SourceFile: relTo(root, path),
		}
		if tlog := parseTransparencyLog(data); tlog != nil {
			sig.TransparencyLog = tlog
		}
		out = append(out, sig)
	}
	return out
}

func signatureCandidates(path string) []string {
	return []string{
		path + ".sig", path + ".asc", path + ".minisig", path + ".pem", path + ".crt",
		path + ".sigstore", path + ".bundle", path + ".bundle.json",
		path + ".intoto.jsonl", path + ".att", path + ".attestation", path + ".attestation.json",
	}
}

func signatureAlgorithm(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "sigstore") || strings.Contains(lower, "bundle") || strings.Contains(lower, "rekor"):
		return "sigstore"
	case strings.HasSuffix(lower, ".minisig"):
		return "minisign"
	case strings.HasSuffix(lower, ".asc"), strings.HasSuffix(lower, ".sig"):
		return "gpg"
	default:
		return "signature-sidecar"
	}
}

func parseTransparencyLog(data []byte) *cyclonedx.SBOMTransparencyLogEntry {
	var doc any
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	entry := findTLogEntry(doc)
	if entry == nil {
		return nil
	}
	out := &cyclonedx.SBOMTransparencyLogEntry{
		LogID:          stringFromAny(firstAny(entry, "logID", "logId", "log_id")),
		UUID:           stringFromAny(firstAny(entry, "uuid", "body")),
		IntegratedTime: stringFromAny(firstAny(entry, "integratedTime", "integrated_time")),
		Checkpoint:     stringFromAny(firstAny(entry, "checkpoint")),
		SignerIdentity: stringFromAny(firstAny(entry, "signerIdentity", "subject")),
		Issuer:         stringFromAny(firstAny(entry, "issuer", "certificateIssuer")),
	}
	if idx, ok := int64FromAny(firstAny(entry, "logIndex", "log_index", "index")); ok {
		out.Index = idx
	}
	if v := firstAny(entry, "inclusionProof", "inclusion_proof"); v != nil {
		if b, err := json.Marshal(v); err == nil {
			out.InclusionProof = string(b)
		}
	}
	if m, ok := firstAny(entry, "logId").(map[string]any); ok && out.LogID == "" {
		out.LogID = stringFromAny(firstAny(m, "keyId", "keyid"))
	}
	return out
}

func findTLogEntry(v any) map[string]any {
	switch x := v.(type) {
	case map[string]any:
		for _, key := range []string{"tlogEntries", "tlog_entries", "transparencyLogEntries"} {
			if arr, ok := x[key].([]any); ok && len(arr) > 0 {
				if m, ok := arr[0].(map[string]any); ok {
					return m
				}
			}
		}
		if _, ok := x["logIndex"]; ok {
			return x
		}
		for _, child := range x {
			if found := findTLogEntry(child); found != nil {
				return found
			}
		}
	case []any:
		for _, child := range x {
			if found := findTLogEntry(child); found != nil {
				return found
			}
		}
	}
	return nil
}

func firstAny(m map[string]any, keys ...string) any {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return nil
}

func stringFromAny(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		if x > 1000000000 {
			return time.Unix(int64(x), 0).UTC().Format(time.RFC3339)
		}
		return strconv.FormatInt(int64(x), 10)
	case map[string]any:
		if b, err := json.Marshal(x); err == nil {
			return string(b)
		}
	}
	return ""
}

func int64FromAny(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case string:
		i, err := strconv.ParseInt(x, 10, 64)
		return i, err == nil
	default:
		return 0, false
	}
}

func extractContainerArchive(path string) (string, func(), error) {
	tmp, err := os.MkdirTemp("", "vulnetix-cdx-rootfs-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	f, err := os.Open(path)
	if err != nil {
		cleanup()
		return "", cleanup, err
	}
	defer f.Close()
	if err := extractTarMaybeGzip(f, tmp); err != nil {
		cleanup()
		return "", cleanup, err
	}
	return tmp, cleanup, nil
}

func extractTarMaybeGzip(r io.Reader, dst string) error {
	br := bufio.NewReader(r)
	var reader io.Reader = br
	if magic, err := br.Peek(2); err == nil && len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return err
		}
		defer gz.Close()
		reader = gz
	}
	tr := tar.NewReader(reader)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := filepath.ToSlash(hdr.Name)
		if strings.Contains(name, "..") {
			continue
		}
		if hdr.Typeflag == tar.TypeReg && strings.HasSuffix(name, ".tar") {
			if err := extractTarMaybeGzip(tr, dst); err != nil {
				continue
			}
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		target := filepath.Join(dst, filepath.FromSlash(name))
		if rel, err := filepath.Rel(dst, target); err != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, tr)
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func dedupeCDXPackages(in []cyclonedx.SBOMPackage) []cyclonedx.SBOMPackage {
	seen := map[string]int{}
	var out []cyclonedx.SBOMPackage
	for _, p := range in {
		if p.Name == "" {
			continue
		}
		key := p.Purl
		if key == "" {
			key = strings.ToLower(p.Ecosystem + ":" + p.Name + "@" + p.Version + ":" + p.SourceType + ":" + p.SourceFile)
		}
		if idx, ok := seen[key]; ok {
			out[idx].Hashes = append(out[idx].Hashes, p.Hashes...)
			out[idx].Licenses = append(out[idx].Licenses, p.Licenses...)
			out[idx].Signatures = append(out[idx].Signatures, p.Signatures...)
			out[idx].Evidence = append(out[idx].Evidence, p.Evidence...)
			continue
		}
		seen[key] = len(out)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem == out[j].Ecosystem {
			return out[i].Name < out[j].Name
		}
		return out[i].Ecosystem < out[j].Ecosystem
	})
	return out
}

func countCDXSources(pkgs []cyclonedx.SBOMPackage) map[string]int {
	out := map[string]int{}
	for _, p := range pkgs {
		key := p.SourceType
		if key == "" {
			key = "unknown"
		}
		out[key]++
	}
	return out
}

func renderCDXSummary(cmd *cobra.Command, s cdxSummary) {
	t := display.NewTerminal()
	var b strings.Builder
	b.WriteString(display.Header(t, "CycloneDX Inventory"))
	b.WriteByte('\n')
	fmt.Fprintf(&b, "  Wrote %s\n", s.OutputFile)
	fmt.Fprintf(&b, "  Packages: %d", s.PackageCount)
	for _, k := range sortedStringKeys(s.SourceCounts) {
		fmt.Fprintf(&b, "  %s=%d", k, s.SourceCounts[k])
	}
	b.WriteByte('\n')
	fmt.Fprintf(&b, "  Files: %d manifest/CI/shell input(s), %d ELF binary component(s)\n", s.ManifestFileCount, s.BinaryCount)
	fmt.Fprintf(&b, "  AIBOM: %d tool(s), %d SDK(s), %d model(s)\n", s.AITools, s.AILibraries, s.AIModels)
	fmt.Fprintf(&b, "  CBOM: %d crypto asset(s), %d library component(s), %d certificate(s)\n", s.CryptoAssets, s.CryptoLibraries, s.CryptoCerts)
	if len(s.Warnings) > 0 {
		b.WriteString("\n")
		b.WriteString(display.Header(t, "Warnings"))
		b.WriteByte('\n')
		for _, w := range s.Warnings {
			fmt.Fprintf(&b, "  %s\n", w)
		}
	}
	fmt.Fprint(cmd.OutOrStdout(), b.String())
}

func writeCDXFile(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

func splitPythonDistInfo(stem string) (string, string) {
	parts := strings.Split(stem, "-")
	for i := 1; i < len(parts); i++ {
		if parts[i] != "" && parts[i][0] >= '0' && parts[i][0] <= '9' {
			return strings.Join(parts[:i], "-"), parts[i]
		}
	}
	return stem, ""
}

func metadataLicense(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "License:") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "License:"))
			if v != "" && v != "UNKNOWN" {
				return []string{v}
			}
		}
	}
	return nil
}

func splitNameVersionDir(name string) (string, string) {
	re := regexp.MustCompile(`^(.+)-([0-9][A-Za-z0-9._+-]*)$`)
	if m := re.FindStringSubmatch(name); m != nil {
		return m[1], m[2]
	}
	return name, ""
}

func splitAtLast(s, sep string) (string, string) {
	i := strings.LastIndex(s, sep)
	if i <= 0 {
		return s, ""
	}
	return s[:i], s[i+len(sep):]
}

func fieldBlock(block string) map[string]string {
	out := map[string]string{}
	var current string
	for _, line := range strings.Split(block, "\n") {
		if strings.HasPrefix(line, " ") && current != "" {
			out[current] += "\n" + strings.TrimSpace(line)
			continue
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			current = line[:idx]
			out[current] = strings.TrimSpace(line[idx+1:])
		}
	}
	return out
}

func licenseValues(v any) []string {
	switch x := v.(type) {
	case string:
		if x != "" {
			return []string{x}
		}
	case []any:
		var out []string
		for _, item := range x {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func cleanInstalledVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	return v
}

func relTo(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}

func nonEmptyString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func sortedStringKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
