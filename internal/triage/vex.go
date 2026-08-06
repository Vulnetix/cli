// Package triage provides VEX generation for vulnerability triage.
package triage

import (
	"encoding/json"
	"fmt"
	"time"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
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

// GenerateCDXVEX produces a CycloneDX document with VEX data for the given
// findings. specVersion defaults to "1.5" if blank.
//
// The document is assembled and validated by the shared writer in
// github.com/Vulnetix/vdb-cyclonedx, which vdb-api and vdb-site also use. This
// function is the adapter from the CLI's finding shape onto it.
//
// It used to be a third independent implementation. The three had drifted far
// enough apart that vdb-api was shipping documents that failed schema
// validation against the version they declared, and this copy was emitting an
// analysis.state of "under_investigation", which has never been a member of the
// CycloneDX enum.
func GenerateCDXVEX(findings []*TriageFinding, specVersion string) ([]byte, error) {
	if specVersion == "" {
		specVersion = "1.5"
	}

	out := make([]cyclonedx.VEXFinding, 0, len(findings))
	for _, f := range findings {
		if f == nil {
			continue
		}
		v := cyclonedx.VEXFinding{
			CVEID:         f.CVEID,
			Package:       f.Package,
			Ecosystem:     f.Ecosystem,
			InstalledVer:  f.InstalledVer,
			FixedVer:      f.FixedVer,
			Status:        f.Status,
			Justification: f.Justification,
			Severity:      f.Severity,
			Properties:    threatModelProperties(f.ThreatModel),
		}
		if f.ActionResponse != "" {
			v.Responses = []string{f.ActionResponse}
		}
		out = append(out, v)
	}

	return cyclonedx.BuildCDXVEX(out, cyclonedx.VEXOptions{
		SpecVersion: specVersion,
		ToolName:    "vulnetix",
		ToolVersion: "cli",
		AuthorName:  "Vulnetix",
	})
}

// threatModelProperties renders the optional threat-model axes as the
// namespaced CycloneDX properties they have always been emitted as.
func threatModelProperties(tm *ThreatModel) map[string]string {
	if tm == nil {
		return nil
	}
	props := map[string]string{}
	for name, value := range map[string]string{
		"threat:attack_vector":       tm.AttackVector,
		"threat:attack_complexity":   tm.AttackComplexity,
		"threat:privileges_required": tm.PrivilegesRequired,
		"threat:user_interaction":    tm.UserInteraction,
		"threat:reachability":        tm.Reachability,
		"threat:exposure":            tm.Exposure,
	} {
		if value != "" {
			props[name] = value
		}
	}
	if len(props) == 0 {
		return nil
	}
	return props
}
