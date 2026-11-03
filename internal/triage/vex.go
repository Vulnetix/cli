// Package triage provides VEX generation for vulnerability triage.
package triage

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/vulnetix/cli/v4/internal/cdx"
	"github.com/vulnetix/cli/v4/internal/vex"
)

// ---------------------------------------------------------------------------
// OpenVEX 0.2.0
// ---------------------------------------------------------------------------

// OpenVEXOptions controls OpenVEX document generation.
type OpenVEXOptions struct {
	// ID is the document identifier. If empty, a URN is generated.
	ID string
	// Author is the document author. Defaults to DefaultOpenVEXAuthor.
	Author string
	// Tooling identifies the tool that generated the document.
	Tooling string
}

// DefaultOpenVEXAuthor is the author of a document whose caller named none.
const DefaultOpenVEXAuthor = "Vulnetix CLI"

// GenerateOpenVEX produces an OpenVEX 0.2.0 document from triage findings.
//
// The output keeps to the 0.2.0 schema, because consumers (and the Vulnetix
// server) read the documents this CLI writes:
//   - an affected statement says what to do in action_statement; there is no
//     `action` object in the spec;
//   - a justification is written only on not_affected and only from the
//     OpenVEX vocabulary; any other reason goes to status_notes;
//   - a product is identified by its versioned purl in @id, with no
//     `versions` or `supplier` members, which the product schema lacks;
//   - fixed stays fixed: a fixed version never turns a statement into
//     not_affected;
//   - a statement is stamped with when the decision was made, when that is
//     known, rather than when the file was rendered.
//
// The CLI has no severity field to put in a statement, so severity is not
// written: impact_statement is the reason a not_affected holds.
func GenerateOpenVEX(findings []*TriageFinding, opts OpenVEXOptions) ([]byte, error) {
	generated := time.Now().UTC()
	docID := opts.ID
	if docID == "" {
		docID = fmt.Sprintf("urn:openvex:cli:%s", generated.Format("20060102T150405Z"))
	}
	if opts.Author == "" {
		opts.Author = DefaultOpenVEXAuthor
	}
	if opts.Tooling == "" {
		opts.Tooling = "vulnetix-cli"
	}
	now := generated.Format(time.RFC3339)

	stmts := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		if f == nil {
			continue
		}
		stmts = append(stmts, openVEXStatement(f, now))
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

// openVEXStatement renders one finding as an OpenVEX 0.2.0 statement.
func openVEXStatement(f *TriageFinding, generated string) map[string]any {
	status := f.Status
	stmt := map[string]any{
		"vulnerability": map[string]string{"name": f.CVEID},
		"status":        status,
		"timestamp":     statementTimestamp(f, generated),
	}

	var notes []string
	reason := strings.TrimSpace(f.ActionResponse)
	justification := strings.TrimSpace(f.Justification)
	standard := vex.Justifications[justification]

	switch status {
	case "not_affected":
		if standard {
			stmt["justification"] = justification
		} else if justification != "" {
			// A reason outside the vocabulary is still the reason; it is the
			// impact statement when nothing better was written.
			if reason == "" {
				reason = justification
			} else {
				notes = append(notes, "justification: "+justification)
			}
		}
		if reason != "" {
			stmt["impact_statement"] = reason
		}
	case "affected":
		action := reason
		if action == "" && f.FixedVer != "" {
			action = fmt.Sprintf("Upgrade %s to %s or later.", productName(f), f.FixedVer)
		}
		if action == "" {
			action = "No fix is recorded. Track the advisory for a fixed release."
		}
		stmt["action_statement"] = action
		if f.FixedVer != "" && reason != "" {
			notes = append(notes, "fixed in "+f.FixedVer)
		}
		if justification != "" {
			notes = append(notes, "justification: "+justification)
		}
	default: // fixed, under_investigation
		if reason != "" {
			notes = append(notes, reason)
		}
		if justification != "" {
			notes = append(notes, "justification: "+justification)
		}
		if status == "fixed" && f.FixedVer != "" {
			notes = append(notes, "fixed in "+f.FixedVer)
		}
	}
	if len(notes) > 0 {
		stmt["status_notes"] = strings.Join(notes, "; ")
	}

	if id := productID(f); id != "" {
		stmt["products"] = []map[string]any{{"@id": id}}
	}
	return stmt
}

// statementTimestamp is when the decision behind a statement was made: the
// memory decision's date, else DecidedAt, else the generation time.
func statementTimestamp(f *TriageFinding, generated string) string {
	if f.Decision != nil {
		if t, err := time.Parse(time.RFC3339, f.Decision.Date); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	if !f.DecidedAt.IsZero() {
		return f.DecidedAt.UTC().Format(time.RFC3339)
	}
	return generated
}

// productID is the statement's product: a purl carrying the installed
// version, so the statement names the exact release it was made about.
func productID(f *TriageFinding) string {
	if f.Package == "" {
		return ""
	}
	if p := cdx.BuildLocalPurl(f.Package, f.InstalledVer, f.Ecosystem); p != "" {
		return p
	}
	if f.Ecosystem == "" {
		return f.Package
	}
	id := fmt.Sprintf("pkg:%s/%s", strings.ToLower(f.Ecosystem), f.Package)
	if f.InstalledVer != "" {
		id += "@" + f.InstalledVer
	}
	return id
}

func productName(f *TriageFinding) string {
	if f.Package != "" {
		return f.Package
	}
	return "the package"
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

	// A VEX statement is about software that exists and is deployed, so the
	// stage at which these claims were captured is operations. The tool version
	// used to be the literal string "cli", which is not a version and told a
	// consumer nothing about which release made the assertion.
	authorship := cdx.Authoring(cyclonedx.ToolVEX, nil, cdx.PhaseOperations)
	return cyclonedx.BuildCDXVEX(out, cyclonedx.VEXOptions{
		SpecVersion: specVersion,
		Authorship:  &authorship,
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
