package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	SBOMVersion  string       // e.g. "SPDX-2.3", "1.5" for CycloneDX
	Supported    bool         // whether the backend accepts this file type
}

// ManifestFiles maps known manifest filenames to their metadata.
var ManifestFiles = map[string]ManifestInfo{
	// JavaScript
	"package-lock.json": {Type: "package-lock.json", Ecosystem: "npm", Language: "javascript", IsLock: true},
	"package.json":      {Type: "package.json", Ecosystem: "npm", Language: "javascript", IsLock: false},
	"yarn.lock":         {Type: "yarn.lock", Ecosystem: "npm", Language: "javascript", IsLock: true},
	"pnpm-lock.yaml":    {Type: "pnpm-lock.yaml", Ecosystem: "npm", Language: "javascript", IsLock: true},
	// Python
	"requirements.txt": {Type: "requirements.txt", Ecosystem: "pypi", Language: "python", IsLock: false},
	"Pipfile.lock":     {Type: "Pipfile.lock", Ecosystem: "pypi", Language: "python", IsLock: true},
	"poetry.lock":      {Type: "poetry.lock", Ecosystem: "pypi", Language: "python", IsLock: true},
	"uv.lock":          {Type: "uv.lock", Ecosystem: "pypi", Language: "python", IsLock: true},
	// Go
	"go.sum": {Type: "go.sum", Ecosystem: "golang", Language: "go", IsLock: true},
	"go.mod": {Type: "go.mod", Ecosystem: "golang", Language: "go", IsLock: false},
	// Ruby
	"Gemfile.lock": {Type: "Gemfile.lock", Ecosystem: "rubygems", Language: "ruby", IsLock: true},
	// Rust
	"Cargo.lock": {Type: "Cargo.lock", Ecosystem: "cargo", Language: "rust", IsLock: true},
	// Java
	"pom.xml":          {Type: "pom.xml", Ecosystem: "maven", Language: "java", IsLock: false},
	"gradle.lockfile":  {Type: "gradle.lockfile", Ecosystem: "maven", Language: "java", IsLock: true},
	// PHP
	"composer.lock": {Type: "composer.lock", Ecosystem: "composer", Language: "php", IsLock: true},
	// .NET
	"packages.lock.json": {Type: "packages.lock.json", Ecosystem: "nuget", Language: "c#", IsLock: true},
	// Swift
	"Package.resolved": {Type: "Package.resolved", Ecosystem: "swift", Language: "swift", IsLock: true},
	// Dart
	"pubspec.lock": {Type: "pubspec.lock", Ecosystem: "pub", Language: "dart", IsLock: true},
	// Elixir
	"mix.lock": {Type: "mix.lock", Ecosystem: "hex", Language: "elixir", IsLock: true},
	// Scala
	"build.lock": {Type: "build.lock", Ecosystem: "maven", Language: "scala", IsLock: true},
	// Kotlin
	"build.gradle.kts": {Type: "build.gradle.kts", Ecosystem: "maven", Language: "kotlin", IsLock: false},
}

// SupportedManifestTypes lists manifest types accepted by the V2 scan endpoint.
var SupportedManifestTypes = map[string]bool{
	"package.json":      true,
	"package-lock.json": true,
	"requirements.txt":  true,
	"Pipfile.lock":      true,
	"go.sum":            true,
	"go.mod":            true,
	"Cargo.lock":        true,
	"Gemfile.lock":      true,
	"pom.xml":           true,
	"composer.lock":     true,
	"yarn.lock":         true,
	"pnpm-lock.yaml":    true,
}

// DetectManifest checks if a filename is a known manifest file.
func DetectManifest(filename string) (*ManifestInfo, bool) {
	base := filepath.Base(filename)
	info, ok := ManifestFiles[base]
	if !ok {
		return nil, false
	}
	return &info, true
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
			supported := specVersion == "1.4" || specVersion == "1.5" || specVersion == "1.6"
			return FileTypeCycloneDX, specVersion, supported
		}
	}

	return FileTypeUnknown, "", false
}
