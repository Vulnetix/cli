package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/vulnetix/cli/internal/cdx/schema"
)

// FileType represents the detected type of a file
type FileType string

const (
	FileTypeManifest  FileType = "manifest"
	FileTypeSPDX      FileType = "spdx"
	FileTypeCycloneDX FileType = "cyclonedx"
	FileTypeUnknown   FileType = "unknown"
)

// ManifestInfo describes a known manifest file
type ManifestInfo struct {
	Type      string // canonical filename used as the manifest "type" parameter
	Ecosystem string
	Language  string
	IsLock    bool
}

// DetectedFile represents a detected scannable file
type DetectedFile struct {
	Path         string
	RelPath      string // relative to scan root
	FileType     FileType
	ManifestInfo *ManifestInfo // non-nil for manifest files
	SBOMVersion  string        // e.g. "SPDX-2.3", "1.5" for CycloneDX
	Supported    bool          // whether the backend accepts this file type
}

// ManifestFiles maps known manifest filenames (exact basename) to their metadata.
var ManifestFiles = map[string]ManifestInfo{
	// ── JavaScript / Node.js ──────────────────────────────────────────────
	"package-lock.json": {Type: "package-lock.json", Ecosystem: "npm", Language: "javascript", IsLock: true},
	"package.json":      {Type: "package.json", Ecosystem: "npm", Language: "javascript", IsLock: false},
	"yarn.lock":         {Type: "yarn.lock", Ecosystem: "npm", Language: "javascript", IsLock: true},
	"pnpm-lock.yaml":    {Type: "pnpm-lock.yaml", Ecosystem: "npm", Language: "javascript", IsLock: true},
	// ── Python ────────────────────────────────────────────────────────────
	"pyproject.toml":   {Type: "pyproject.toml", Ecosystem: "pypi", Language: "python", IsLock: false},
	"requirements.txt": {Type: "requirements.txt", Ecosystem: "pypi", Language: "python", IsLock: false},
	"requirements.in":  {Type: "requirements.in", Ecosystem: "pypi", Language: "python", IsLock: false},
	"Pipfile":          {Type: "Pipfile", Ecosystem: "pypi", Language: "python", IsLock: false},
	"Pipfile.lock":     {Type: "Pipfile.lock", Ecosystem: "pypi", Language: "python", IsLock: true},
	"poetry.lock":      {Type: "poetry.lock", Ecosystem: "pypi", Language: "python", IsLock: true},
	"uv.lock":          {Type: "uv.lock", Ecosystem: "pypi", Language: "python", IsLock: true},
	// ── Go ────────────────────────────────────────────────────────────────
	"go.sum": {Type: "go.sum", Ecosystem: "golang", Language: "go", IsLock: true},
	"go.mod": {Type: "go.mod", Ecosystem: "golang", Language: "go", IsLock: false},
	// ── Ruby ──────────────────────────────────────────────────────────────
	"Gemfile":      {Type: "Gemfile", Ecosystem: "rubygems", Language: "ruby", IsLock: false},
	"Gemfile.lock": {Type: "Gemfile.lock", Ecosystem: "rubygems", Language: "ruby", IsLock: true},
	// ── Rust ──────────────────────────────────────────────────────────────
	"Cargo.toml": {Type: "Cargo.toml", Ecosystem: "cargo", Language: "rust", IsLock: false},
	"Cargo.lock": {Type: "Cargo.lock", Ecosystem: "cargo", Language: "rust", IsLock: true},
	// ── Java / Gradle ─────────────────────────────────────────────────────
	"pom.xml":         {Type: "pom.xml", Ecosystem: "maven", Language: "java", IsLock: false},
	"build.gradle":    {Type: "build.gradle", Ecosystem: "maven", Language: "java", IsLock: false},
	"gradle.lockfile": {Type: "gradle.lockfile", Ecosystem: "maven", Language: "java", IsLock: true},
	// ── Kotlin / Gradle ───────────────────────────────────────────────────
	"build.gradle.kts": {Type: "build.gradle.kts", Ecosystem: "maven", Language: "kotlin", IsLock: false},
	// ── PHP / Composer ────────────────────────────────────────────────────
	"composer.json": {Type: "composer.json", Ecosystem: "composer", Language: "php", IsLock: false},
	"composer.lock": {Type: "composer.lock", Ecosystem: "composer", Language: "php", IsLock: true},
	// ── .NET / NuGet ──────────────────────────────────────────────────────
	"packages.lock.json": {Type: "packages.lock.json", Ecosystem: "nuget", Language: "c#", IsLock: true},
	"paket.dependencies": {Type: "paket.dependencies", Ecosystem: "nuget", Language: "c#", IsLock: false},
	"paket.lock":         {Type: "paket.lock", Ecosystem: "nuget", Language: "c#", IsLock: true},
	// ── Swift ─────────────────────────────────────────────────────────────
	"Package.swift":    {Type: "Package.swift", Ecosystem: "swift", Language: "swift", IsLock: false},
	"Package.resolved": {Type: "Package.resolved", Ecosystem: "swift", Language: "swift", IsLock: true},
	// ── Dart / Flutter ────────────────────────────────────────────────────
	"pubspec.yaml": {Type: "pubspec.yaml", Ecosystem: "pub", Language: "dart", IsLock: false},
	"pubspec.lock": {Type: "pubspec.lock", Ecosystem: "pub", Language: "dart", IsLock: true},
	// ── Elixir ────────────────────────────────────────────────────────────
	"mix.exs":  {Type: "mix.exs", Ecosystem: "hex", Language: "elixir", IsLock: false},
	"mix.lock": {Type: "mix.lock", Ecosystem: "hex", Language: "elixir", IsLock: true},
	// ── Scala / sbt ───────────────────────────────────────────────────────
	"build.sbt":  {Type: "build.sbt", Ecosystem: "maven", Language: "scala", IsLock: false},
	"build.lock": {Type: "build.lock", Ecosystem: "maven", Language: "scala", IsLock: true},
	// ── Docker / OCI container files ─────────────────────────────────────
	"Dockerfile":    {Type: "Dockerfile", Ecosystem: "docker", Language: "docker", IsLock: false},
	"Containerfile": {Type: "Dockerfile", Ecosystem: "docker", Language: "docker", IsLock: false},
	// ── Bazel ─────────────────────────────────────────────────────────────
	"WORKSPACE":       {Type: "WORKSPACE", Ecosystem: "bazel", Language: "starlark", IsLock: false},
	"WORKSPACE.bazel": {Type: "WORKSPACE", Ecosystem: "bazel", Language: "starlark", IsLock: false},
	"MODULE.bazel":    {Type: "MODULE.bazel", Ecosystem: "bazel", Language: "starlark", IsLock: false},
	"BUCK":            {Type: "BUCK", Ecosystem: "buck", Language: "starlark", IsLock: false},
	"BUCK2":           {Type: "BUCK2", Ecosystem: "buck", Language: "starlark", IsLock: false},
	// ── C/C++ / Conan ─────────────────────────────────────────────────────
	"conanfile.txt": {Type: "conanfile.txt", Ecosystem: "conan", Language: "c++", IsLock: false},
	"conanfile.py":  {Type: "conanfile.py", Ecosystem: "conan", Language: "c++", IsLock: false},
	"conan.lock":    {Type: "conan.lock", Ecosystem: "conan", Language: "c++", IsLock: true},
	// ── C/C++ / vcpkg ─────────────────────────────────────────────────────
	"vcpkg.json": {Type: "vcpkg.json", Ecosystem: "vcpkg", Language: "c++", IsLock: false},
	// ── CocoaPods (iOS/macOS) ─────────────────────────────────────────────
	"Podfile":      {Type: "Podfile", Ecosystem: "cocoapods", Language: "swift", IsLock: false},
	"Podfile.lock": {Type: "Podfile.lock", Ecosystem: "cocoapods", Language: "swift", IsLock: true},
	// ── Carthage (iOS/macOS) ──────────────────────────────────────────────
	"Cartfile":          {Type: "Cartfile", Ecosystem: "carthage", Language: "swift", IsLock: false},
	"Cartfile.resolved": {Type: "Cartfile.resolved", Ecosystem: "carthage", Language: "swift", IsLock: true},
	// ── Julia ─────────────────────────────────────────────────────────────
	"Project.toml":  {Type: "Project.toml", Ecosystem: "julia", Language: "julia", IsLock: false},
	"Manifest.toml": {Type: "Manifest.toml", Ecosystem: "julia", Language: "julia", IsLock: true},
	// ── Crystal ───────────────────────────────────────────────────────────
	"shard.yml":  {Type: "shard.yml", Ecosystem: "crystal", Language: "crystal", IsLock: false},
	"shard.lock": {Type: "shard.lock", Ecosystem: "crystal", Language: "crystal", IsLock: true},
	// ── Deno ──────────────────────────────────────────────────────────────
	"deno.json": {Type: "deno.json", Ecosystem: "deno", Language: "typescript", IsLock: false},
	"deno.lock": {Type: "deno.lock", Ecosystem: "deno", Language: "typescript", IsLock: true},
	// ── R / CRAN ──────────────────────────────────────────────────────────
	"DESCRIPTION": {Type: "DESCRIPTION", Ecosystem: "cran", Language: "r", IsLock: false},
	"renv.lock":   {Type: "renv.lock", Ecosystem: "cran", Language: "r", IsLock: true},
	// ── Erlang / rebar3 ───────────────────────────────────────────────────
	"rebar.config": {Type: "rebar.config", Ecosystem: "erlang", Language: "erlang", IsLock: false},
	"rebar.lock":   {Type: "rebar.lock", Ecosystem: "erlang", Language: "erlang", IsLock: true},
	// ── Haskell / Stack ───────────────────────────────────────────────────
	"stack.yaml": {Type: "stack.yaml", Ecosystem: "stack", Language: "haskell", IsLock: false},
	// ── Haskell / Cabal ───────────────────────────────────────────────────
	"cabal.project.freeze": {Type: "cabal.project.freeze", Ecosystem: "cabal", Language: "haskell", IsLock: true},
	// ── OCaml / opam (exact filename) ────────────────────────────────────
	"opam": {Type: "opam", Ecosystem: "opam", Language: "ocaml", IsLock: false},
	// ── Nix ───────────────────────────────────────────────────────────────
	"flake.nix":  {Type: "flake.nix", Ecosystem: "nix", Language: "nix", IsLock: false},
	"flake.lock": {Type: "flake.lock", Ecosystem: "nix", Language: "nix", IsLock: true},
	// ── Zig ───────────────────────────────────────────────────────────────
	"build.zig.zon": {Type: "build.zig.zon", Ecosystem: "zig", Language: "zig", IsLock: false},
	// ── CMake / CPM ───────────────────────────────────────────────────────
	"CPM.cmake": {Type: "CPM.cmake", Ecosystem: "cpm", Language: "cmake", IsLock: false},
	// ── Meson ─────────────────────────────────────────────────────────────
	"meson.build": {Type: "meson.build", Ecosystem: "meson", Language: "c", IsLock: false},
}

// ManifestExtensions maps file extensions to manifest metadata.
// Used for files whose names include a project-specific prefix (e.g. foo.csproj, main.tf).
var ManifestExtensions = map[string]ManifestInfo{
	".csproj":        {Type: "*.csproj", Ecosystem: "nuget", Language: "c#", IsLock: false},
	".tf":            {Type: "*.tf", Ecosystem: "terraform", Language: "hcl", IsLock: false},
	".opam":          {Type: "*.opam", Ecosystem: "opam", Language: "ocaml", IsLock: false},
	".cabal":         {Type: "*.cabal", Ecosystem: "cabal", Language: "haskell", IsLock: false},
	".dockerfile":    {Type: "Dockerfile", Ecosystem: "docker", Language: "docker", IsLock: false},
	".containerfile": {Type: "Dockerfile", Ecosystem: "docker", Language: "docker", IsLock: false},
}

// SupportedManifestTypes lists manifest types that have a local parser implemented.
// Files detected but absent from this map are shown as "[not supported]" in scan output.
var SupportedManifestTypes = map[string]bool{
	// JavaScript / Node.js
	"package.json":      true,
	"package-lock.json": true,
	"yarn.lock":         true,
	"pnpm-lock.yaml":    true,
	// Python
	"pyproject.toml":   true,
	"requirements.txt": true,
	"requirements.in":  true,
	"Pipfile":          true,
	"Pipfile.lock":     true,
	"poetry.lock":      true,
	"uv.lock":          true,
	// Go
	"go.sum": true,
	"go.mod": true,
	// Ruby
	"Gemfile":      true,
	"Gemfile.lock": true,
	// Rust
	"Cargo.toml": true,
	"Cargo.lock": true,
	// Java / Gradle
	"pom.xml":          true,
	"build.gradle":     true,
	"gradle.lockfile":  true,
	"build.gradle.kts": true,
	// PHP / Composer
	"composer.json": true,
	"composer.lock": true,
	// .NET / NuGet
	"packages.lock.json": true,
	"paket.dependencies": true,
	"paket.lock":         true,
	"*.csproj":           true,
	// Swift
	"Package.swift":    true,
	"Package.resolved": true,
	// Dart / Flutter
	"pubspec.yaml": true,
	"pubspec.lock": true,
	// Elixir
	"mix.exs":  true,
	"mix.lock": true,
	// Scala / sbt
	"build.sbt":  true,
	"build.lock": true,
	// Docker / OCI container files
	"Dockerfile": true,
	// Terraform
	"*.tf": true,
	// GitHub Actions
	"github-actions.yml": true,
	// C/C++ / Conan
	"conanfile.txt": true,
	"conan.lock":    true,
	// C/C++ / vcpkg
	"vcpkg.json": true,
	// CocoaPods
	"Podfile":      true,
	"Podfile.lock": true,
	// Carthage
	"Cartfile":          true,
	"Cartfile.resolved": true,
	// Julia
	"Project.toml":  true,
	"Manifest.toml": true,
	// Crystal
	"shard.yml":  true,
	"shard.lock": true,
	// Deno
	"deno.json": true,
	"deno.lock": true,
	// R / CRAN
	"DESCRIPTION": true,
	"renv.lock":   true,
	// Erlang / rebar3
	"rebar.config": true,
	"rebar.lock":   true,
	// Haskell / Stack
	"stack.yaml": true,
	// Haskell / Cabal
	"*.cabal":              true,
	"cabal.project.freeze": true,
	// OCaml / opam
	"*.opam": true,
	"opam":   true,
	// Nix
	"flake.nix":  true,
	"flake.lock": true,
	// Zig
	"build.zig.zon": true,
	// Meson
	"meson.build": true,
	// Bazel
	"WORKSPACE":    true,
	"MODULE.bazel": true,
	// Buck
	"BUCK":  true,
	"BUCK2": true,
	// CMake / CPM
	"CPM.cmake":      true,
	"CMakeLists.txt": true, // content-checked: only detected when file contains CPMAddPackage
}

// DetectManifest checks if a file is a known manifest.
// It checks in order: exact basename → file extension → path pattern (GitHub Actions).
func DetectManifest(filename string) (*ManifestInfo, bool) {
	base := filepath.Base(filename)

	// 1. Exact basename match.
	if info, ok := ManifestFiles[base]; ok {
		return &info, true
	}

	// 2. Extension-based match (e.g. foo.csproj, main.tf, mylib.opam, myapp.cabal).
	ext := strings.ToLower(filepath.Ext(base))
	if info, ok := ManifestExtensions[ext]; ok {
		// Avoid matching obviously wrong files (e.g. a random .tf that isn't Terraform).
		// All extension matches are considered valid — the parser handles false positives.
		infoCopy := info
		return &infoCopy, true
	}

	// 3. Content-checked: CMakeLists.txt with CPMAddPackage calls.
	if base == "CMakeLists.txt" {
		content, err := os.ReadFile(filename)
		if err == nil && strings.Contains(string(content), "CPMAddPackage") {
			info := ManifestInfo{
				Type:      "CMakeLists.txt",
				Ecosystem: "cpm",
				Language:  "cmake",
				IsLock:    false,
			}
			return &info, true
		}
	}

	// 4. Path-pattern: GitHub Actions workflow files under .github/workflows/.
	lowerBase := strings.ToLower(base)
	if strings.HasSuffix(lowerBase, ".yml") || strings.HasSuffix(lowerBase, ".yaml") {
		slash := filepath.ToSlash(filename)
		if strings.Contains(slash, "/.github/workflows/") ||
			strings.HasPrefix(slash, ".github/workflows/") {
			info := ManifestInfo{
				Type:      "github-actions.yml",
				Ecosystem: "github-actions",
				Language:  "yaml",
				IsLock:    false,
			}
			return &info, true
		}
	}

	return nil, false
}

// DetectSBOM reads the first bytes of a JSON file and determines if it's an SPDX or CycloneDX document.
// Returns the file type, version string, and whether it's valid/supported.
func DetectSBOM(filePath string) (FileType, string, bool) {
	if !strings.HasSuffix(strings.ToLower(filePath), ".json") {
		return FileTypeUnknown, "", false
	}

	f, err := os.Open(filePath)
	if err != nil {
		return FileTypeUnknown, "", false
	}
	defer f.Close()

	// Read first 4KB
	buf := make([]byte, 4096)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return FileTypeUnknown, "", false
	}

	// Try to parse as JSON
	var data map[string]interface{}
	if err := json.Unmarshal(buf[:n], &data); err != nil {
		// Try with the full file if the first 4KB wasn't valid JSON
		fullData, err2 := os.ReadFile(filePath)
		if err2 != nil {
			return FileTypeUnknown, "", false
		}
		if err := json.Unmarshal(fullData, &data); err != nil {
			return FileTypeUnknown, "", false
		}
	}

	// Check for SPDX: has spdxVersion AND SPDXID fields
	if spdxVersion, ok := data["spdxVersion"].(string); ok {
		if _, hasID := data["SPDXID"]; hasID {
			supported := spdxVersion == "SPDX-2.3"
			return FileTypeSPDX, spdxVersion, supported
		}
	}

	// Check for CycloneDX: has bomFormat == "CycloneDX" AND specVersion
	if bomFormat, ok := data["bomFormat"].(string); ok && bomFormat == "CycloneDX" {
		if specVersion, ok := data["specVersion"].(string); ok {
			// Validate against embedded schemas (highest version first, short-circuit).
			fullData, readErr := os.ReadFile(filePath)
			if readErr != nil {
				return FileTypeCycloneDX, specVersion, false
			}
			validatedVersion, valErr := schema.ValidateCDX(fullData)
			if valErr != nil {
				return FileTypeCycloneDX, specVersion, false
			}
			return FileTypeCycloneDX, validatedVersion, true
		}
	}

	return FileTypeUnknown, "", false
}
