package license

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/vulnetix/cli/internal/cdx"
)

const CDXSourceName = "vulnetix-license-analyzer"

// FindingsToCDXVulnerabilities converts license findings to CycloneDX vulnerability entries.
func FindingsToCDXVulnerabilities(findings []Finding, packages []PackageLicense) []cdx.Vulnerability {
	// Build component bom-ref lookup for Affects.
	bomRefMap := map[string]string{} // "name@version" → bom-ref
	for _, pkg := range packages {
		key := pkg.PackageName + "@" + pkg.PackageVersion
		if _, ok := bomRefMap[key]; !ok {
			bomRefMap[key] = fmt.Sprintf("pkg:%s/%s@%s", strings.ToLower(pkg.Ecosystem), pkg.PackageName, pkg.PackageVersion)
		}
	}

	vulns := make([]cdx.Vulnerability, 0, len(findings))
	for _, f := range findings {
		v := cdx.Vulnerability{
			BOMRef:      f.ID,
			ID:          f.ID,
			Source:      &cdx.Source{Name: CDXSourceName},
			Description: f.Description,
			Ratings: []cdx.Rating{
				{
					Severity: f.Severity,
					Score:    f.Confidence,
					Method:   "other",
					Source:   &cdx.Source{Name: CDXSourceName},
				},
			},
			Properties: []cdx.Property{
				{Name: "vulnetix:license-category", Value: f.Category},
				{Name: "vulnetix:license-severity", Value: f.Severity},
				{Name: "vulnetix:license-confidence", Value: fmt.Sprintf("%.2f", f.Confidence)},
			},
		}

		// Add package-specific properties.
		if f.Package.LicenseSpdxID != "" {
			v.Properties = append(v.Properties, cdx.Property{
				Name: "vulnetix:license-spdx-id", Value: f.Package.LicenseSpdxID,
			})
		}
		if f.Package.SourceFile != "" {
			v.Properties = append(v.Properties, cdx.Property{
				Name: "vulnetix:source-file", Value: f.Package.SourceFile,
			})
		}

		// Add Affects ref if we can find the component.
		pkgKey := f.Package.PackageName + "@" + f.Package.PackageVersion
		if ref, ok := bomRefMap[pkgKey]; ok {
			v.Affects = []cdx.Affect{{Ref: ref}}
		}

		// Serialize evidence as properties.
		for i, ev := range f.Evidence {
			prefix := fmt.Sprintf("vulnetix:evidence-%d", i)
			v.Properties = append(v.Properties,
				cdx.Property{Name: prefix + ":rule", Value: ev.Rule},
				cdx.Property{Name: prefix + ":result", Value: ev.Result},
			)
		}

		vulns = append(vulns, v)
	}

	return vulns
}

// MergeBOM reads an existing BOM from path, replaces all vulnerabilities with the
// given source name, appends the new vulnerabilities, and writes back.
// If the file doesn't exist, it creates a minimal BOM with just the new vulnerabilities.
func MergeBOM(existingPath string, newVulns []cdx.Vulnerability, source string) error {
	var bom cdx.BOM

	data, err := os.ReadFile(existingPath)
	if err == nil {
		if err := json.Unmarshal(data, &bom); err != nil {
			return fmt.Errorf("failed to parse existing BOM: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read BOM: %w", err)
	} else {
		// No existing BOM — create minimal structure.
		bom = cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: "1.7",
			Version:     1,
		}
	}

	// Remove all vulnerabilities from the given source.
	filtered := make([]cdx.Vulnerability, 0, len(bom.Vulnerabilities))
	for _, v := range bom.Vulnerabilities {
		if v.Source == nil || v.Source.Name != source {
			filtered = append(filtered, v)
		}
	}

	// Append new ones.
	bom.Vulnerabilities = append(filtered, newVulns...)

	// Write back.
	out, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal BOM: %w", err)
	}

	if err := os.MkdirAll(existingPath[:strings.LastIndex(existingPath, "/")], 0o755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	return os.WriteFile(existingPath, out, 0o644)
}
