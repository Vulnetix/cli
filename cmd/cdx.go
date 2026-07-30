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
	"github.com/vulnetix/cli/v3/internal/binpkg"
	"github.com/vulnetix/cli/v3/internal/cbom"
	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/ecosystems"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/license"
	"github.com/vulnetix/cli/v3/internal/scan"
)

// cdxCmd is named for the format it emits. `sbom` is an alias rather than the
// canonical name on purpose: an SPDX generator will land beside it as its own
// command, and until then "sbom" resolves to CycloneDX — the format this tool
// prefers and produces natively everywhere else (.vulnetix/*.cdx.json, VEX,
// AIBOM, CBOM).
var cdxCmd = &cobra.Command{
	Use:     "cdx [path]",
	Aliases: []string{"sbom"},
	Short:   "Generate a standalone CycloneDX SBOM without VDB lookup or upload",
	Long: `Generate one local CycloneDX document containing the package SBOM, AI Bill
of Materials (AIBOM), and Cryptography Bill of Materials (CBOM).

The command is offline: it reads local manifests, installed package directories,
container root filesystems/archives, CI/CD pipeline files, shell scripts,
compiled binaries and signature sidecars, then writes a CycloneDX JSON file. It
does not query the Vulnetix VDB, upload data, update memory.yaml, enforce quality
gates or contact a container daemon.

Discovery sources:
  • package manifests and lockfiles
  • installed-package directories (node_modules, site-packages, vendor, gems, …)
  • container root filesystem package databases (dpkg, apk, pacman)
  • package installs in Dockerfiles, compose, Kubernetes and Helm files
  • package installs in CI/CD pipeline files (GitHub Actions, GitLab CI,
    CircleCI, Buildkite, Azure Pipelines, Tekton, Concourse, Jenkins, …)
  • package installs in shell scripts, Makefiles and task recipes
  • packages embedded in compiled binaries: Go build info, Rust
    cargo-auditable data and JVM archive coordinates, attributed to the OS
    package that installed them where a package database says so

The metadata written for each component matches what "vulnetix sca" records:
purl, ecosystem, scope/environment, direct-ness, source file and source type,
installed path, checksums, licenses (SPDX ids where recognised), discovery
evidence, signature/transparency-log provenance, and the resolved dependency
graph.

"vulnetix sbom" is an alias for this command: CycloneDX is the preferred output
format, and a future SPDX generator will be its own command.

Examples:
  vulnetix cdx
  vulnetix cdx ./service -o cyclonedx-json
  vulnetix cdx --container-rootfs ./rootfs
  vulnetix cdx --container-archive ./image.tar
  vulnetix cdx --no-aibom --no-cbom --output-file build/sbom.cdx.json
  vulnetix sbom                                  # alias for vulnetix cdx`,
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
	NoBinaryPackages  bool
	NoLicenses        bool
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
	BinaryPackages    int            `json:"binaryPackages"`
	ArtifactsExamined int            `json:"artifactsExamined"`
	UnownedBinaries   int            `json:"unownedBinaries"`
	DependencyEdges   int            `json:"dependencyEdges"`
	LicensedPackages  int            `json:"licensedPackages"`
	PreservedVulns    int            `json:"preservedVulnerabilities,omitempty"`
	AITools           int            `json:"aiTools"`
	AILibraries       int            `json:"aiLibraries"`
	AIModels          int            `json:"aiModels"`
	CryptoAssets      int            `json:"cryptoAssets"`
	CryptoLibraries   int            `json:"cryptoLibraries"`
	CryptoCerts       int            `json:"cryptoCertificates"`
	Warnings          []string       `json:"warnings,omitempty"`
}

// cdxInventory is everything the discovery passes produced, before it is handed
// to the CycloneDX builder.
type cdxInventory struct {
	Packages     []cyclonedx.SBOMPackage
	Dependencies []cyclonedx.SBOMDependency
	// ScanPackages are the manifest-parsed packages in their native form, kept so
	// license detection and dependency-graph construction see exactly what `sca`
	// sees.
	ScanPackages   []scan.ScopedPackage
	ManifestGroups []scan.ManifestGroup
	ManifestFiles  int
	BinaryFiles    int
	BinaryPackages int
	Examined       int
	Unowned        int
	Warnings       []string
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
	cdxCmd.Flags().Bool("no-binary-analysis", false, "Skip binary analysis (ELF file components and embedded package metadata)")
	cdxCmd.Flags().Bool("no-binary-packages", false, "Analyse binaries but do not emit the packages embedded in them (Go build info, cargo-auditable, JVM archives)")
	cdxCmd.Flags().Bool("no-licenses", false, "Skip license detection for discovered packages")
	cdxCmd.Flags().Bool("no-aibom", false, "Skip AIBOM detection and omit AI components")
	cdxCmd.Flags().Bool("no-cbom", false, "Skip CBOM detection and omit cryptographic components")
	cdxCmd.Flags().Bool("no-signatures", false, "Skip local signature, attestation and transparency-log sidecar discovery")
	cdxCmd.Flags().Bool("include-home", false, "Also inspect user-scoped package caches for installed packages")
	cdxCmd.Flags().Bool("cdx-include-ignored", false, "Include files matched by .gitignore (default: gitignored paths are skipped)")
	// Accepted for callers that reach the command through its `sbom` alias and
	// spell the flag to match. Hidden so only one name is advertised.
	cdxCmd.Flags().Bool("sbom-include-ignored", false, "Alias for --cdx-include-ignored")
	_ = cdxCmd.Flags().MarkHidden("sbom-include-ignored")
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

	inv := collectCDXPackages(opts)
	warnings := inv.Warnings

	licensed := 0
	if !opts.NoLicenses {
		licensed = applyCDXLicenses(&inv)
	}

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
		Packages:         inv.Packages,
		Dependencies:     inv.Dependencies,
		AIDetections:     aiDet,
		CryptoDetections: cryptoDet,
	}, cyclonedx.SBOMOptions{
		SpecVersion:     opts.SpecVersion,
		ToolName:        "vulnetix-cdx",
		ToolVersion:     version,
		Project:         aibomProject(gitCtx, sysInfo),
		CanonicalSPDXID: license.CanonicalSPDXID,
	})
	if err != nil {
		return err
	}

	// The default output path is the same file `scan`/`sca` use as scan memory, so
	// carry over any vulnerability and VEX analysis already recorded there. An
	// offline inventory run must not silently erase findings.
	bomData, preserved, err := preserveCDXVulnerabilities(opts.OutputFile, bomData)
	if err != nil {
		warnings = append(warnings, "preserving existing findings: "+err.Error())
	}

	if err := writeCDXFile(opts.OutputFile, bomData); err != nil {
		return err
	}
	summary := cdxSummary{
		OutputFile:        opts.OutputFile,
		PackageCount:      len(inv.Packages),
		SourceCounts:      countCDXSources(inv.Packages),
		ManifestFileCount: inv.ManifestFiles,
		BinaryCount:       inv.BinaryFiles,
		BinaryPackages:    inv.BinaryPackages,
		ArtifactsExamined: inv.Examined,
		UnownedBinaries:   inv.Unowned,
		DependencyEdges:   len(inv.Dependencies),
		LicensedPackages:  licensed,
		PreservedVulns:    preserved,
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
	noBinaryPackages, _ := cmd.Flags().GetBool("no-binary-packages")
	noLicenses, _ := cmd.Flags().GetBool("no-licenses")
	noAIBOM, _ := cmd.Flags().GetBool("no-aibom")
	noCBOM, _ := cmd.Flags().GetBool("no-cbom")
	noSignatures, _ := cmd.Flags().GetBool("no-signatures")
	includeHome, _ := cmd.Flags().GetBool("include-home")
	includeIgnored, _ := cmd.Flags().GetBool("cdx-include-ignored")
	if aliasSpelling, _ := cmd.Flags().GetBool("sbom-include-ignored"); aliasSpelling {
		includeIgnored = true
	}
	rootfs, _ := cmd.Flags().GetStringArray("container-rootfs")
	archives, _ := cmd.Flags().GetStringArray("container-archive")
	aibomCatalog, _ := cmd.Flags().GetString("aibom-catalog")
	cbomCatalog, _ := cmd.Flags().GetString("cbom-catalog")
	noBuiltinAIBOM, _ := cmd.Flags().GetBool("no-builtin-aibom-catalog")
	noBuiltinCBOM, _ := cmd.Flags().GetBool("no-builtin-cbom-catalog")
	return cdxRunOptions{
		RootPath: abs, Depth: depth, Exclude: exclude, Ignore: ignore, Output: output, OutputFile: outputFile, SpecVersion: specVersion,
		NoManifests: noManifests, NoFilesystem: noFilesystem, NoContainerfiles: noContainerfiles, NoCI: noCI, NoShell: noShell,
		NoBinaryAnalysis: noBinary, NoBinaryPackages: noBinaryPackages, NoLicenses: noLicenses,
		NoAIBOM: noAIBOM, NoCBOM: noCBOM, NoSignatures: noSignatures, IncludeHome: includeHome,
		IncludeIgnored: includeIgnored, ContainerRootfs: rootfs, ContainerArchives: archives,
		AIBOMCatalog: aibomCatalog, CBOMCatalog: cbomCatalog, NoBuiltinAIBOM: noBuiltinAIBOM, NoBuiltinCBOM: noBuiltinCBOM,
	}, nil
}

func collectCDXPackages(opts cdxRunOptions) cdxInventory {
	inv := cdxInventory{}

	// ── Manifests, containerfiles, CI/CD pipelines and shell scripts ─────────
	if !opts.NoManifests || !opts.NoContainerfiles || !opts.NoCI || !opts.NoShell {
		files, err := scan.WalkForScanFiles(scan.WalkOptions{
			RootPath: opts.RootPath, MaxDepth: opts.Depth,
			Excludes:         append(append([]string{}, opts.Exclude...), opts.Ignore...),
			RespectGitignore: !opts.IncludeIgnored,
		})
		if err != nil {
			inv.Warnings = append(inv.Warnings, "manifest discovery: "+err.Error())
		}
		// filePackages/fileEcosystems feed BuildManifestGroups, which is what
		// resolves the dependency graph `sca` publishes.
		filePackages := map[string][]scan.ScopedPackage{}
		fileEcosystems := map[string]string{}
		for _, f := range files {
			if !includeCDXDetectedFile(f, opts) {
				continue
			}
			inv.ManifestFiles++
			pkgs, err := scan.ParseManifestWithScope(f.Path, f.ManifestInfo.Type)
			if err != nil {
				inv.Warnings = append(inv.Warnings, f.RelPath+": "+err.Error())
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
			normalized := make([]scan.ScopedPackage, 0, len(pkgs))
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
				normalized = append(normalized, p)
				inv.Packages = append(inv.Packages, cdxPackageFromScan(p, opts.RootPath, !opts.NoSignatures))
			}
			inv.ScanPackages = append(inv.ScanPackages, normalized...)
			filePackages[f.RelPath] = normalized
			fileEcosystems[f.RelPath] = f.ManifestInfo.Ecosystem
		}
		inv.ManifestGroups = scan.BuildManifestGroups(filePackages, fileEcosystems)
		scan.PopulateInstalledEdges(inv.ManifestGroups, opts.RootPath)
	}

	// ── Installed-package trees ──────────────────────────────────────────────
	if !opts.NoFilesystem {
		inv.Packages = append(inv.Packages, collectInstalledPackages(opts)...)
	}

	// ── Compiled artefacts in the project itself ─────────────────────────────
	if !opts.NoBinaryAnalysis {
		inv.merge(collectCDXBinaries(opts, opts.RootPath, opts.RootPath, ""))
	}

	// ── Container root filesystems and archives ──────────────────────────────
	for _, rootfs := range opts.ContainerRootfs {
		abs, err := filepath.Abs(rootfs)
		if err != nil {
			inv.Warnings = append(inv.Warnings, rootfs+": "+err.Error())
			continue
		}
		inv.Packages = append(inv.Packages, collectContainerDBPackages(abs, abs, filepath.Base(abs), !opts.NoSignatures)...)
		if !opts.NoFilesystem {
			inv.Packages = append(inv.Packages, collectInstalledPackages(cdxRunOptions{RootPath: abs, IncludeHome: false, NoSignatures: opts.NoSignatures})...)
		}
		if !opts.NoBinaryAnalysis {
			inv.merge(collectCDXBinaries(opts, abs, abs, filepath.Base(abs)))
		}
	}
	for _, archive := range opts.ContainerArchives {
		dir, cleanup, err := extractContainerArchive(archive)
		if err != nil {
			inv.Warnings = append(inv.Warnings, archive+": "+err.Error())
			continue
		}
		inv.Packages = append(inv.Packages, collectContainerDBPackages(dir, dir, filepath.Base(archive), !opts.NoSignatures)...)
		if !opts.NoFilesystem {
			inv.Packages = append(inv.Packages, collectInstalledPackages(cdxRunOptions{RootPath: dir, IncludeHome: false, NoSignatures: opts.NoSignatures})...)
		}
		if !opts.NoBinaryAnalysis {
			inv.merge(collectCDXBinaries(opts, dir, dir, filepath.Base(archive)))
		}
		cleanup()
	}

	inv.Packages = dedupeCDXPackages(inv.Packages)
	inv.Dependencies = buildCDXDependencies(inv)
	// Report distinct components, not observations: the same Go module linked into
	// ten release binaries is one package.
	inv.BinaryPackages = 0
	for _, p := range inv.Packages {
		if p.SourceType == scan.SourceTypeBinary && p.Type != "file" {
			inv.BinaryPackages++
		}
	}
	return inv
}

// merge folds one discovery pass's output into the inventory.
func (inv *cdxInventory) merge(other cdxInventory) {
	inv.Packages = append(inv.Packages, other.Packages...)
	inv.Dependencies = append(inv.Dependencies, other.Dependencies...)
	inv.Warnings = append(inv.Warnings, other.Warnings...)
	inv.ManifestFiles += other.ManifestFiles
	inv.BinaryFiles += other.BinaryFiles
	inv.BinaryPackages += other.BinaryPackages
	inv.Examined += other.Examined
	inv.Unowned += other.Unowned
}

// buildCDXDependencies resolves the dependency graph the same way `sca` does —
// from manifest-group edges — and appends the edges recovered from compiled
// artefacts. Refs are the bom-refs this command assigns, so the shared builder
// keeps every edge whose endpoints became components and drops the rest.
func buildCDXDependencies(inv cdxInventory) []cyclonedx.SBOMDependency {
	refs := make(map[string]string, len(inv.Packages))
	for _, p := range inv.Packages {
		// `file` components are binaries on disk, not packages. They share a name
		// with the package that installed them ("curl"), so letting them into this
		// index would make a manifest edge for a package resolve to a file.
		if p.Type == "file" {
			continue
		}
		key := p.Name + "@" + p.Version
		if _, exists := refs[key]; !exists {
			refs[key] = p.BOMRef
		}
	}
	var out []cyclonedx.SBOMDependency
	for _, dep := range cdx.BuildDependencies(inv.ManifestGroups, refs) {
		out = append(out, cyclonedx.SBOMDependency{Ref: dep.Ref, DependsOn: dep.DependsOn})
	}
	// Edges carried on the inventory already use bom-refs (see collectCDXBinaries).
	out = append(out, inv.Dependencies...)
	return out
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
	case scan.IsCIPipelineFile(f.ManifestInfo):
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
	method := nonEmptyString(p.SourceType, "manifest")
	out.Evidence = []cyclonedx.SBOMEvidence{{
		Method: method, Locator: p.SourceFile, Confidence: cdxEvidenceConfidence(p),
	}}
	if includeSignatures && p.SourceFile != "" {
		out.Signatures = discoverSignaturesForFile(root, p.SourceFile)
	}
	return out
}

// cdxEvidenceConfidence grades the evidence behind a discovered package. A
// declared dependency in a manifest is a fact; a package name lifted out of an
// `apt-get install` line in a CI job or shell script is an inference — the
// command may be conditional, commented out at runtime, or never executed — so it
// must not claim the same confidence.
func cdxEvidenceConfidence(p scan.ScopedPackage) string {
	switch p.SourceType {
	case scan.SourceTypeCommand:
		if p.Version != "" {
			return "medium" // a pinned install command names an exact artefact
		}
		return "low"
	case scan.SourceTypeBinary:
		return "high"
	default:
		return "high"
	}
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

// collectCDXBinaries runs the two binary passes over one tree:
//
//   - scan.ScanContainerFilesystem hashes every ELF and emits it as a `file`
//     component (what the container binary analysis has always reported), and
//   - binpkg reads the package metadata compiled into those binaries plus any
//     JVM archive or PE/Mach-O executable beside them, turning them into real
//     package components with a dependency graph.
//
// When the tree carries a package database, each artefact is attributed to the OS
// package that installed it, and artefacts no package claims are counted — a
// binary that arrived outside the package manager is exactly what an image
// inventory needs to surface.
func collectCDXBinaries(opts cdxRunOptions, root, labelRoot, sourceLabel string) cdxInventory {
	inv := cdxInventory{}
	result := scan.ScanContainerFilesystem(root)
	inv.BinaryFiles = result.ELFCount
	includeSignatures := !opts.NoSignatures

	binaryRefs := map[string]string{}
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
			Properties: map[string]string{},
		}
		if b.ELFType != "" {
			pkg.Properties["vulnetix:binary/elf-type"] = b.ELFType
		}
		if b.ELFArch != "" {
			pkg.Properties["vulnetix:binary/arch"] = b.ELFArch
		}
		if includeSignatures {
			pkg.Signatures = discoverSignaturesForFile(labelRoot, rel)
		}
		pkg.BOMRef = cdxBinaryRef(sourceLabel, rel, b.Hashes.SHA256)
		binaryRefs[b.Path] = pkg.BOMRef
		inv.Packages = append(inv.Packages, pkg)
	}

	if opts.NoBinaryPackages {
		return inv
	}

	owners := binpkg.OwnerIndex(nil)
	if binpkg.HasFileOwnership(root) {
		owners = binpkg.BuildOwnerIndex(root)
	}
	tree := binpkg.ScanTree(binpkg.TreeOptions{Root: root, Owners: owners})
	inv.Examined = tree.Examined
	inv.Unowned = len(tree.Unowned)
	for _, warn := range tree.Errors {
		inv.Warnings = append(inv.Warnings, "binary analysis: "+warn)
	}

	// Package components recovered from inside the artefacts.
	refByKey := map[string]string{}
	for _, p := range tree.Packages {
		artifactRel := relTo(labelRoot, p.BinaryPath)
		locator := artifactRel
		if sourceLabel != "" {
			locator = sourceLabel + ":" + artifactRel
		}
		out := cyclonedx.SBOMPackage{
			Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem,
			Scope:      nonEmptyString(p.Scope, scan.ScopeProduction),
			Purl:       cyclonedx.SBOMPurl(p.Name, p.Version, p.Ecosystem),
			SourceFile: locator, SourceType: scan.SourceTypeBinary,
			InstalledPath: artifactRel, IsDirect: p.IsDirect,
			Evidence: []cyclonedx.SBOMEvidence{{
				Method: p.Method, Locator: locator, Detail: p.Detail,
				Confidence: nonEmptyString(p.Confidence, "medium"),
			}},
			Properties: map[string]string{"vulnetix:binary/discovered-in": artifactRel},
		}
		if p.Checksum != "" {
			out.Hashes = append(out.Hashes, cyclonedx.SBOMHash{Alg: "H1", Content: p.Checksum})
		}
		out.BOMRef = cdxPackageRef(out)
		refByKey[p.Name+"@"+p.Version] = out.BOMRef
		inv.Packages = append(inv.Packages, out)
		inv.BinaryPackages++
	}

	// Module/crate graph recovered from the artefacts, translated into bom-refs.
	for _, edge := range tree.Edges {
		from, ok := refByKey[edge.From]
		if !ok {
			continue
		}
		var on []string
		for _, target := range edge.DependsOn {
			if ref, ok := refByKey[target]; ok {
				on = append(on, ref)
			}
		}
		if len(on) > 0 {
			inv.Dependencies = append(inv.Dependencies, cyclonedx.SBOMDependency{Ref: from, DependsOn: on})
		}
	}

	// Ownership: the OS package component (from the package database pass) becomes
	// the parent of the files it installed, and every artefact records its owner.
	// The ref→index map matters: an image can hold tens of thousands of binaries,
	// and searching the component slice per property would be quadratic.
	indexByRef := make(map[string]int, len(inv.Packages))
	for i, p := range inv.Packages {
		if p.Type == "file" {
			indexByRef[p.BOMRef] = i
		}
	}
	ownerEdges := map[string][]string{}
	for _, art := range tree.Artifacts {
		ref, hasComponent := binaryRefs[art.Path]
		idx, indexed := -1, false
		if hasComponent {
			idx, indexed = indexByRef[ref]
		}
		setProp := func(name, value string) {
			if !indexed || value == "" {
				return
			}
			if inv.Packages[idx].Properties == nil {
				inv.Packages[idx].Properties = map[string]string{}
			}
			inv.Packages[idx].Properties[name] = value
		}
		if art.Owner != nil {
			ownerRef := cyclonedx.SBOMPurl(art.Owner.Name, art.Owner.Version, art.Owner.Ecosystem)
			if indexed && ownerRef != "" {
				ownerEdges[ownerRef] = append(ownerEdges[ownerRef], ref)
			}
			setProp("vulnetix:binary/owner-package", art.Owner.Key())
			setProp("vulnetix:binary/owner-ecosystem", art.Owner.Ecosystem)
		} else if len(owners) > 0 {
			// Only meaningful when a readable package database exists; otherwise
			// "no owner" says nothing about how the file got there.
			setProp("vulnetix:binary/unpackaged", "true")
		}
		setProp("vulnetix:binary/format", art.Format)
		for k, v := range art.Attributes {
			setProp("vulnetix:binary/"+k, v)
		}
	}
	for ownerRef, files := range ownerEdges {
		inv.Dependencies = append(inv.Dependencies, cyclonedx.SBOMDependency{Ref: ownerRef, DependsOn: files})
	}
	return inv
}

// cdxBinaryRef builds a stable bom-ref for a binary file component. The content
// hash is included so the same path in two images is two components.
func cdxBinaryRef(sourceLabel, rel, sha256 string) string {
	ref := "urn:file:"
	if sourceLabel != "" {
		ref += sanitizeCDXRef(sourceLabel) + ":"
	}
	ref += sanitizeCDXRef(rel)
	if len(sha256) >= 12 {
		ref += "@" + sha256[:12]
	}
	return ref
}

// cdxPackageRef assigns the bom-ref for a package component: its purl when it has
// one, otherwise a synthetic urn. Assigning it here (rather than letting the
// builder default it) is what lets the dependency graph reference components by
// ref before the document is built.
func cdxPackageRef(p cyclonedx.SBOMPackage) string {
	if p.BOMRef != "" {
		return p.BOMRef
	}
	if p.Purl != "" {
		return p.Purl
	}
	return "urn:package:" + sanitizeCDXRef(p.Ecosystem) + ":" + sanitizeCDXRef(p.Name) + ":" + sanitizeCDXRef(p.Version)
}

// sanitizeCDXRef makes a value safe for a CycloneDX bom-ref, which may not
// contain whitespace.
func sanitizeCDXRef(v string) string {
	return strings.Join(strings.Fields(v), "_")
}

// applyCDXLicenses resolves licenses for the manifest-parsed packages with the
// same detector `sca` uses (manifest license fields, then the embedded SPDX
// database) and attaches them to the matching components. Components that already
// carry a license from their installed metadata keep it. Returns how many
// components ended up with a license.
func applyCDXLicenses(inv *cdxInventory) int {
	if len(inv.ScanPackages) > 0 {
		detected := license.DetectLicenses(inv.ScanPackages, inv.ManifestGroups)
		byKey := make(map[string]string, len(detected))
		for _, pl := range detected {
			if pl.LicenseSpdxID == "" || pl.LicenseSpdxID == "UNKNOWN" {
				continue
			}
			byKey[pl.PackageName+"@"+pl.PackageVersion] = pl.LicenseSpdxID
		}
		for i := range inv.Packages {
			if len(inv.Packages[i].Licenses) > 0 {
				continue
			}
			if lic, ok := byKey[inv.Packages[i].Name+"@"+inv.Packages[i].Version]; ok {
				inv.Packages[i].Licenses = []string{lic}
			}
		}
	}
	licensed := 0
	for i := range inv.Packages {
		if len(inv.Packages[i].Licenses) > 0 {
			licensed++
		}
	}
	return licensed
}

// preserveCDXVulnerabilities carries the `vulnerabilities` array — and any
// component a preserved entry points at — from an existing document at path into
// the freshly built one. The default output path is the same file `scan` and
// `sca` write, and those records (including VEX analysis) are the repository's
// finding history: an inventory-only run must not delete them.
//
// Returns the rewritten document and how many vulnerability entries were carried
// over. A missing or unparseable file is not an error for the caller: the new
// document is returned unchanged.
func preserveCDXVulnerabilities(path string, fresh []byte) ([]byte, int, error) {
	existingRaw, err := os.ReadFile(path)
	if err != nil {
		return fresh, 0, nil // nothing on disk yet
	}
	var existing map[string]any
	if err := json.Unmarshal(existingRaw, &existing); err != nil {
		return fresh, 0, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	vulns, _ := existing["vulnerabilities"].([]any)
	if len(vulns) == 0 {
		return fresh, 0, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(fresh, &doc); err != nil {
		return fresh, 0, err
	}

	// Components the preserved findings affect but this run did not rediscover
	// (a dependency removed from the manifest, or a scan that ran with narrower
	// flags) are carried over too, so no `affects` ref dangles.
	present := map[string]bool{}
	freshComponents, _ := doc["components"].([]any)
	for _, c := range freshComponents {
		if m, ok := c.(map[string]any); ok {
			if ref, ok := m["bom-ref"].(string); ok {
				present[ref] = true
			}
		}
	}
	needed := map[string]bool{}
	for _, v := range vulns {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		affects, _ := m["affects"].([]any)
		for _, a := range affects {
			am, ok := a.(map[string]any)
			if !ok {
				continue
			}
			if ref, ok := am["ref"].(string); ok && !present[ref] {
				needed[ref] = true
			}
		}
	}
	if len(needed) > 0 {
		existingComponents, _ := existing["components"].([]any)
		for _, c := range existingComponents {
			m, ok := c.(map[string]any)
			if !ok {
				continue
			}
			ref, _ := m["bom-ref"].(string)
			if !needed[ref] {
				continue
			}
			props, _ := m["properties"].([]any)
			m["properties"] = append(props, map[string]any{
				"name":  "vulnetix:sbom/carried-over",
				"value": "true",
			})
			freshComponents = append(freshComponents, m)
			present[ref] = true
		}
		doc["components"] = freshComponents
	}
	doc["vulnerabilities"] = vulns

	merged, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fresh, 0, err
	}
	// The carried-over material came from a document this tool wrote, but validate
	// anyway: writing an invalid SBOM is worse than losing the history, and the
	// caller surfaces the warning.
	if _, violations, verr := cyclonedx.ValidateCycloneDX(merged); verr != nil {
		return fresh, 0, verr
	} else if len(violations) > 0 {
		return fresh, 0, fmt.Errorf("merged document failed validation at %s: %s",
			violations[0].Path, violations[0].Message)
	}
	return merged, len(vulns), nil
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
		// Resolve the purl and the bom-ref here rather than leaving them to the
		// builder, so the dependency graph can reference components by ref — and so
		// a component's ref is its purl whenever it has one.
		if p.Purl == "" {
			p.Purl = cyclonedx.SBOMPurl(p.Name, p.Version, p.Ecosystem)
		}
		p.BOMRef = cdxPackageRef(p)
		key := p.Purl
		if key == "" {
			key = strings.ToLower(p.Ecosystem + ":" + p.Name + "@" + p.Version + ":" + p.SourceType + ":" + p.SourceFile)
		}
		if idx, ok := seen[key]; ok {
			// The same package found in several places contributes its evidence, but
			// identical hashes/licenses must not pile up: nine release binaries
			// linking one Go module carry one H1 sum, not nine copies of it.
			out[idx].Hashes = mergeCDXHashes(out[idx].Hashes, p.Hashes)
			out[idx].Licenses = mergeCDXStrings(out[idx].Licenses, p.Licenses)
			out[idx].Signatures = mergeCDXSignatures(out[idx].Signatures, p.Signatures)
			out[idx].Evidence = append(out[idx].Evidence, p.Evidence...)
			if p.IsDirect {
				out[idx].IsDirect = true
			}
			for k, v := range p.Properties {
				if out[idx].Properties == nil {
					out[idx].Properties = map[string]string{}
				}
				if _, exists := out[idx].Properties[k]; !exists {
					out[idx].Properties[k] = v
				}
			}
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

func mergeCDXHashes(dst, src []cyclonedx.SBOMHash) []cyclonedx.SBOMHash {
	seen := make(map[string]bool, len(dst)+len(src))
	for _, h := range dst {
		seen[h.Alg+"="+h.Content] = true
	}
	for _, h := range src {
		key := h.Alg + "=" + h.Content
		if h.Content == "" || seen[key] {
			continue
		}
		seen[key] = true
		dst = append(dst, h)
	}
	return dst
}

func mergeCDXStrings(dst, src []string) []string {
	seen := make(map[string]bool, len(dst)+len(src))
	for _, v := range dst {
		seen[v] = true
	}
	for _, v := range src {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		dst = append(dst, v)
	}
	return dst
}

func mergeCDXSignatures(dst, src []cyclonedx.SBOMSignature) []cyclonedx.SBOMSignature {
	seen := make(map[string]bool, len(dst)+len(src))
	for _, s := range dst {
		seen[s.Algorithm+"="+s.Value+"="+s.SourceFile] = true
	}
	for _, s := range src {
		key := s.Algorithm + "=" + s.Value + "=" + s.SourceFile
		if seen[key] {
			continue
		}
		seen[key] = true
		dst = append(dst, s)
	}
	return dst
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
	fmt.Fprintf(&b, "  Binaries: %d artefact(s) examined, %d package(s) recovered from embedded metadata", s.ArtifactsExamined, s.BinaryPackages)
	if s.UnownedBinaries > 0 {
		fmt.Fprintf(&b, ", %d not claimed by any OS package", s.UnownedBinaries)
	}
	b.WriteByte('\n')
	fmt.Fprintf(&b, "  Graph: %d dependency edge set(s); Licenses: %d component(s)\n", s.DependencyEdges, s.LicensedPackages)
	if s.PreservedVulns > 0 {
		fmt.Fprintf(&b, "  Carried over %d existing vulnerability record(s) from %s\n", s.PreservedVulns, s.OutputFile)
	}
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
