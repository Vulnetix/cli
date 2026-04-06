// Package triage provides VEX generation for vulnerability triage.
package triage

import (
	"encoding/json"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// OpenVEX 0.2.0
// ---------------------------------------------------------------------------

// OpenVEXOptions controls OpenVEX document generation.
type OpenVEXOptions struct {
	// ID is the document identifier. If empty, a URN is generated.
	ID string
	// Author is the document author.
	Author string
	// Tooling identifies the tool that generated the document.
	Tooling string
}

// GenerateOpenVEX produces an OpenVEX 0.2.0 document from triage findings.
func GenerateOpenVEX(findings []*TriageFinding, opts OpenVEXOptions) ([]byte, error) {
	docID := opts.ID
	if docID == "" {
		docID = fmt.Sprintf("urn:openvex:cli:%s", time.Now().UTC().Format("20060102T150405Z"))
	}
	if opts.Author == "" {
		opts.Author = "Vulnetix"
	}
	if opts.Tooling == "" {
		opts.Tooling = "vulnetix-cli"
	}

	now := time.Now().UTC().Format(time.RFC3339)

	stmts := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		stmt := map[string]any{
			"vulnerability": map[string]string{
				"name": f.CVEID,
			},
			"status":    f.Status,
			"timestamp": now,
		}

		if f.Justification != "" {
			stmt["justification"] = f.Justification
		}

		if f.ActionResponse != "" {
			stmt["action"] = map[string]string{
				"status":    f.ActionResponse,
				"timestamp": now,
			}
		}

		if f.Severity != "" {
			stmt["impact_statement"] = fmt.Sprintf("Severity: %s", f.Severity)
		}

		if f.FixedVer != "" {
			stmt["fixed_version"] = f.FixedVer
			if f.Justification == "" {
				stmt["justification"] = "vulnerable_code_not_present"
				stmt["status"] = "not_affected"
			}
		}

		if f.Package != "" {
			stmt["products"] = []map[string]any{
				{
					"@id":      fmt.Sprintf("pkg:%s/%s", f.Ecosystem, f.Package),
					"supplier": f.Package,
					"versions": []map[string]string{
						{"version": f.InstalledVer},
					},
					"subcomponents": []map[string]string{
						{"@id": fmt.Sprintf("pkg:%s/%s@%s", f.Ecosystem, f.Package, f.InstalledVer)},
					},
				},
			}
		}

		stmts = append(stmts, stmt)
	}

	doc := map[string]any{
		"@context":   "https://openvex.dev/ns/v0.2.0",
		"@id":        docID,
		"author":     opts.Author,
		"timestamp":  now,
		"version":    1,
		"tooling":    opts.Tooling,
		"statements": stmts,
	}

	return json.MarshalIndent(doc, "", "  ")
}

// ---------------------------------------------------------------------------
// CycloneDX VEX (CycloneDX 1.5+ with VEX profile)
// ---------------------------------------------------------------------------

// GenerateCDXVEX produces a minimal CycloneDX document with VEX data for the
// given findings. The output is CycloneDX 1.5 JSON with vulnerabilities declared.
func GenerateCDXVEX(findings []*TriageFinding, specVersion string) ([]byte, error) {
	if specVersion == "" {
		specVersion = "1.5"
	}

	vulns := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		vuln := map[string]any{
			"id":       f.CVEID,
			"analysis": cdxAnalysis(f.Status),
		}

		if f.Severity != "" && f.Severity != "unknown" {
			vuln["ratings"] = []map[string]any{
				{
					"source":   map[string]string{"name": "vulnetix"},
					"severity": f.Severity,
				},
			}
		}

		if f.ThreatModel != nil {
			props := []map[string]any{}
			if f.ThreatModel.AttackVector != "" {
				props = append(props, map[string]any{"name": "threat:attack_vector", "value": f.ThreatModel.AttackVector})
			}
			if f.ThreatModel.AttackComplexity != "" {
				props = append(props, map[string]any{"name": "threat:attack_complexity", "value": f.ThreatModel.AttackComplexity})
			}
			if f.ThreatModel.PrivilegesRequired != "" {
				props = append(props, map[string]any{"name": "threat:privileges_required", "value": f.ThreatModel.PrivilegesRequired})
			}
			if f.ThreatModel.UserInteraction != "" {
				props = append(props, map[string]any{"name": "threat:user_interaction", "value": f.ThreatModel.UserInteraction})
			}
			if f.ThreatModel.Reachability != "" {
				props = append(props, map[string]any{"name": "threat:reachability", "value": f.ThreatModel.Reachability})
			}
			if f.ThreatModel.Exposure != "" {
				props = append(props, map[string]any{"name": "threat:exposure", "value": f.ThreatModel.Exposure})
			}
			if len(props) > 0 {
				vuln["properties"] = props
			}
		}

		vulns = append(vulns, vuln)
	}

	components := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		if f.Package == "" {
			continue
		}
		components = append(components, map[string]any{
			"type":    "library",
			"name":    f.Package,
			"version": f.InstalledVer,
			"purl":    fmt.Sprintf("pkg:%s/%s@%s", f.Ecosystem, f.Package, f.InstalledVer),
		})
	}

	doc := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": specVersion,
		"version":     1,
	}
	if len(components) > 0 {
		doc["components"] = components
	}
	if len(vulns) > 0 {
		doc["vulnerabilities"] = vulns
	}

	return json.MarshalIndent(doc, "", "  ")
}

func cdxAnalysis(status string) map[string]string {
	switch status {
	case "not_affected":
		return map[string]string{"state": "not_affected"}
	case "fixed":
		return map[string]string{"state": "resolved"}
	case "affected":
		return map[string]string{
			"state":  "exploitable",
			"detail": "vulnerability has been triaged and confirmed",
		}
	default:
		return map[string]string{
			"state":  "under_investigation",
			"detail": "vulnerability is being investigated",
		}
	}
}
