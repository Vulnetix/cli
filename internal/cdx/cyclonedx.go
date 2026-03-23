package cdx

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vulnetix/cli/internal/scan"
)

// CycloneDX BOM structs for 1.6 and 1.7 output.

// BOM is the top-level CycloneDX Bill of Materials.
type BOM struct {
	BOMFormat       string          `json:"bomFormat"`
	SpecVersion     string          `json:"specVersion"`
	SerialNumber    string          `json:"serialNumber"`
	Version         int             `json:"version"`
	Metadata        *Metadata       `json:"metadata,omitempty"`
	Components      []Component     `json:"components,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// Metadata describes the BOM creation context.
type Metadata struct {
	Timestamp string  `json:"timestamp"`
	Tools     *Tools  `json:"tools,omitempty"`
}

// Tools holds tool information in CycloneDX format.
type Tools struct {
	Components []Component `json:"components,omitempty"`
}

// Component represents a software component.
type Component struct {
	Type       string      `json:"type"`
	BOMRef     string      `json:"bom-ref,omitempty"`
	Name       string      `json:"name"`
	Version    string      `json:"version,omitempty"`
	Scope      string      `json:"scope,omitempty"`
	Purl       string      `json:"purl,omitempty"`
	Properties []Property  `json:"properties,omitempty"`
}

// Property is a name-value pair.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Vulnerability represents a CycloneDX vulnerability entry.
type Vulnerability struct {
	BOMRef      string      `json:"bom-ref,omitempty"`
	ID          string      `json:"id"`
	Source      *Source     `json:"source,omitempty"`
	Ratings     []Rating    `json:"ratings,omitempty"`
	Description string      `json:"description,omitempty"`
	Affects     []Affect    `json:"affects,omitempty"`
	Analysis    *Analysis   `json:"analysis,omitempty"`
	Properties  []Property  `json:"properties,omitempty"`
	Advisories  []Advisory  `json:"advisories,omitempty"`
}

// Source identifies where vulnerability data comes from.
type Source struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

// Rating is a vulnerability scoring entry.
type Rating struct {
	Score    float64 `json:"score"`
	Severity string  `json:"severity,omitempty"`
	Method   string  `json:"method,omitempty"`
	Source   *Source `json:"source,omitempty"`
}

// Affect identifies a component affected by a vulnerability.
type Affect struct {
	Ref string `json:"ref"`
}

// Analysis contains vulnerability analysis state.
type Analysis struct {
	State string `json:"state,omitempty"`
}

// Advisory is an external advisory reference.
type Advisory struct {
	URL string `json:"url,omitempty"`
}

// scoreTypeToMethod maps internal score type names to CycloneDX method identifiers.
var scoreTypeToMethod = map[string]string{
	"epss":          "other",
	"coalition_ess": "other",
	"cvssv4":        "CVSSv4",
	"cvss4":         "CVSSv4",
	"cvssv3.1":      "CVSSv31",
	"cvss3.1":       "CVSSv31",
	"cvssv3.0":      "CVSSv3",
	"cvss3.0":       "CVSSv3",
	"cvss3":         "CVSSv3",
	"cvssv3":        "CVSSv3",
	"cvssv2":        "CVSSv2",
	"cvss2":         "CVSSv2",
	"cvssv2.0":      "CVSSv2",
}

// BuildFromScanTasks creates a CycloneDX BOM from completed scan tasks.
func BuildFromScanTasks(tasks []*scan.ScanTask, specVersion string) *BOM {
	if specVersion == "" {
		specVersion = "1.7"
	}

	bom := &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  specVersion,
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Version:      1,
		Metadata: &Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: &Tools{
				Components: []Component{
					{
						Type:    "application",
						Name:    "vulnetix",
						Version: "cli",
					},
				},
			},
		},
	}

	// Track components by package name+version to deduplicate
	componentRefs := map[string]string{} // "name@version" -> bom-ref

	allVulns := scan.AllVulns(tasks)

	for _, v := range allVulns {
		// Ensure the affected component exists
		compKey := v.PackageName + "@" + v.PackageVer
		bomRef, exists := componentRefs[compKey]
		if !exists && v.PackageName != "" {
			bomRef = fmt.Sprintf("pkg:%s@%s", v.PackageName, v.PackageVer)
			componentRefs[compKey] = bomRef
			bom.Components = append(bom.Components, Component{
				Type:    "library",
				BOMRef:  bomRef,
				Name:    v.PackageName,
				Version: v.PackageVer,
			})
		}

		// Build vulnerability entry
		vuln := Vulnerability{
			BOMRef: v.VulnID,
			ID:     v.VulnID,
			Source: &Source{
				Name: "Vulnetix VDB",
				URL:  "https://vulnetix.com",
			},
		}

		// Add ratings from scores
		for _, s := range v.Scores {
			method := scoreTypeToMethod[s.Type]
			if method == "" {
				method = "other"
			}
			r := Rating{
				Score:    s.Score,
				Severity: v.Severity,
				Method:   method,
			}
			if s.Source != "" {
				r.Source = &Source{Name: s.Source}
			}
			if s.Type == "epss" || s.Type == "coalition_ess" {
				r.Source = &Source{Name: s.Type}
			}
			vuln.Ratings = append(vuln.Ratings, r)
		}

		// Add affects reference
		if bomRef != "" {
			vuln.Affects = append(vuln.Affects, Affect{Ref: bomRef})
		}

		// Handle malicious packages
		if v.IsMalicious {
			vuln.Analysis = &Analysis{State: "exploitable"}
			vuln.Properties = append(vuln.Properties, Property{
				Name:  "vulnetix:malware",
				Value: "true",
			})
		}

		// Add source file property
		if v.SourceFile != "" {
			vuln.Properties = append(vuln.Properties, Property{
				Name:  "vulnetix:source-file",
				Value: v.SourceFile,
			})
		}

		bom.Vulnerabilities = append(bom.Vulnerabilities, vuln)
	}

	return bom
}

// WriteJSON writes the BOM as indented JSON to the writer.
func (b *BOM) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(b)
}

// FormatSpec returns the format string for CLI display.
func FormatSpec(specVersion string) string {
	return fmt.Sprintf("CycloneDX %s", specVersion)
}

// ValidSpecVersions returns the list of supported CycloneDX spec versions.
func ValidSpecVersions() []string {
	return []string{"1.6", "1.7"}
}

// NormalizeFormat maps user-facing format names to spec versions or output type.
// Returns (specVersion, isRawJSON).
func NormalizeFormat(format string) (string, bool) {
	switch strings.ToLower(format) {
	case "cdx17", "cyclonedx17", "1.7", "cdx":
		return "1.7", false
	case "cdx16", "cyclonedx16", "1.6":
		return "1.6", false
	case "json", "raw":
		return "", true
	default:
		return "1.7", false
	}
}
