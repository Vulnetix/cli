package upload

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vulnetix/cli/v3/internal/cdx/schema"
)

// DiscoveredFile is an artifact file ready for upload.
type DiscoveredFile struct {
	Path   string
	Format string // "cyclonedx" | "spdx" | "sarif" | "openvex" | "csaf_vex"
}

// nonArtifactNames lists filenames that live in .vulnetix/ but are not uploadable artifacts.
var nonArtifactNames = map[string]bool{
	"credentials.json": true,
	"memory.yaml":      true,
	"memory.yml":       true,
}

// DiscoverVulnetixFiles returns all uploadable artifact files in dir.
// Files are matched by extension (*.json, *.xml, *.sarif), filtered by
// non-artifact names, and accepted only when DetectFormat returns a
// recognised format (not "auto"). CycloneDX files are also validated
// against the embedded JSON schema; schema failures produce a warning
// and skip the file rather than aborting the whole discovery.
func DiscoverVulnetixFiles(dir string) ([]DiscoveredFile, []string, error) {
	globs := []string{"*.json", "*.xml", "*.sarif"}

	var found []DiscoveredFile
	var warnings []string

	for _, pattern := range globs {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return nil, nil, fmt.Errorf("glob %s: %w", pattern, err)
		}
		for _, path := range matches {
			base := filepath.Base(path)

			// Skip known non-artifact files.
			baseLower := strings.ToLower(base)
			if nonArtifactNames[baseLower] {
				continue
			}
			if strings.HasSuffix(baseLower, ".rules") ||
				strings.HasSuffix(baseLower, ".yaml") ||
				strings.HasSuffix(baseLower, ".yml") {
				continue
			}

			data, err := os.ReadFile(path)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("skip %s: %v", path, err))
				continue
			}

			format := DetectFormat(path, data)
			if format == "auto" {
				// Not a recognised artifact format.
				continue
			}

			// Validate CycloneDX locally; warn and skip on failure.
			if format == "cyclonedx" {
				if _, err := schema.ValidateCDX(data); err != nil {
					warnings = append(warnings, fmt.Sprintf("skip %s: CDX schema validation failed: %v", path, err))
					continue
				}
			}

			found = append(found, DiscoveredFile{Path: path, Format: format})
		}
	}

	return found, warnings, nil
}

// FindVulnetixDir returns the first .vulnetix/ directory found by looking
// at the current working directory first, then the user home directory.
// Returns ("", false) if neither exists.
func FindVulnetixDir() (string, bool) {
	// Project-relative
	projectDir := filepath.Join(".", ".vulnetix")
	if info, err := os.Stat(projectDir); err == nil && info.IsDir() {
		return projectDir, true
	}

	// Home directory
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false
	}
	homeDir := filepath.Join(home, ".vulnetix")
	if info, err := os.Stat(homeDir); err == nil && info.IsDir() {
		return homeDir, true
	}

	return "", false
}
