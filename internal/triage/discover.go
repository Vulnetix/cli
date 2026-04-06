package triage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vulnetix/cli/internal/memory"
)

// CDXVuln is a minimal representation of a vulnerability in a CycloneDX BOM.
type CDXVuln struct {
	ID string `json:"id"`
}

// CDXBOM is a minimal CycloneDX BOM for extracting vulnerability IDs.
type CDXBOM struct {
	Vulnerabilities []CDXVuln      `json:"vulnerabilities,omitempty"`
	Components      []CDXComponent `json:"components,omitempty"`
}

// CDXComponent is a minimal component entry in a BOM.
type CDXComponent struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	BOMRef  string `json:"bom-ref,omitempty"`
}

// DiscoverCVEs returns a list of CVE IDs to triage.
func DiscoverCVEs(sbomPath, memPath string, all bool, statusFilter string) ([]string, error) {
	cveSet := make(map[string]bool)

	// 1. Extract CVEs from SBOM vulnerabilities section.
	if _, err := os.Stat(sbomPath); err == nil {
		ids, err := extractVulnIds(sbomPath)
		if err != nil {
			return nil, fmt.Errorf("reading SBOM %s: %w", sbomPath, err)
		}
		for _, id := range ids {
			cveSet[id] = true
		}
	}

	// 2. Cross-reference memory.yaml for existing findings and status.
	mem, err := loadMemory(memPath)
	if err != nil {
		mem = &memory.Memory{Version: "1"}
	}

	// If no SBOM found, use known finding ids from memory.
	if len(cveSet) == 0 && mem.Findings != nil {
		for id := range mem.Findings {
			cveSet[id] = true
		}
	}

	if all {
		return mapKeys(cveSet), nil
	}

	// Filter by status.
	if statusFilter != "" {
		var result []string
		for id := range cveSet {
			f := mem.GetFinding(id)
			if f != nil && f.Status == statusFilter {
				result = append(result, id)
			} else if f == nil {
				// New finding from SBOM with no memory entry.
				result = append(result, id)
			}
		}
		return result, nil
	}

	// Default: return vulns with status "under_investigation" or no entry.
	var result []string
	for id := range cveSet {
		f := mem.GetFinding(id)
		if f == nil || f.Status == "" || f.Status == "under_investigation" {
			result = append(result, id)
		}
	}
	return result, nil
}

func extractVulnIds(sbomPath string) ([]string, error) {
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return nil, err
	}

	var bom CDXBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(bom.Vulnerabilities))
	for _, v := range bom.Vulnerabilities {
		if v.ID != "" {
			ids = append(ids, v.ID)
		}
	}
	return ids, nil
}

// ComponentInfo extracts package name, version, and ecosystem from a CDX component or PURL.
func ComponentInfo(pkg string) (name, version, ecosystem string) {
	// Try to parse pkg as a PURL first.
	if len(pkg) > 7 && pkg[:4] == "pkg:" {
		// pkg:<ecosystem>/<name>@<version>
		rest := pkg[4:]
		if i := rest[0]; i == '/' {
			rest = rest[1:]
		}
		if idx := rest[0]; idx == '@' {
			rest = rest[1:]
		} else {
			idx := rest[0]
			if idx == '/' {
				rest = rest[1:]
			}
		}
		// Split ecosystem/name@version.
		for i, c := range rest {
			if c == '/' {
				ecosystem = rest[:i]
				rest = rest[i+1:]
				break
			}
		}
		for i, c := range rest {
			if c == '@' {
				name = rest[:i]
				version = rest[i+1:]
				return
			}
		}
		name = rest
		return
	}
	return "", "", ""
}

func loadMemory(memPath string) (*memory.Memory, error) {
	if _, err := os.Stat(memPath); os.IsNotExist(err) {
		return &memory.Memory{Version: "1"}, nil
	}
	return memory.Load(filepath.Dir(memPath))
}

func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
