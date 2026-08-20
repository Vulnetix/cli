package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vulnetix/cli/v3/internal/sast"
	"github.com/vulnetix/cli/v3/internal/triage"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// ─────────────────────────────────────────────────────────────────────────
// jail_artifacts.go — writing the gate's evidence to disk.
//
// The server decides the verdict and hands back statements; this file renders
// them with the same shared writers `sca`, `fix` and the scan family already
// use, so a jail artefact is byte-compatible with everything else the CLI emits.
// ─────────────────────────────────────────────────────────────────────────

// Default artefact paths, alongside the rest of the .vulnetix directory.
const (
	defaultJailVEXPath   = ".vulnetix/jail.vex.json"
	defaultJailSARIFPath = ".vulnetix/jail.sarif"
)

// jailFallbackJustification is used only if the server ever sends a statement
// without one. See writeJailVEX.
const jailFallbackJustification = "component_present_and_in_scope"

// writeJailVEX renders the VEX statements and returns the path written.
//
// Every statement is forced to carry a justification, and that assertion is the
// point of this function rather than a nicety. triage.GenerateOpenVEX rewrites a
// statement that has a fixed_version and an empty justification to
// status "not_affected" — the precise inverse of what a jail asserts, which is
// "affected, past policy, and a fix exists". A document claiming the opposite of
// the verdict that produced it is worse than no document, so the CLI does not
// trust the server to have filled the field in; it checks.
func writeJailVEX(resp *vdb.CliJailResponse, path, format string) (string, error) {
	if resp == nil || resp.Vex == nil || len(resp.Vex.Statements) == 0 {
		return "", nil
	}
	if path == "" {
		path = defaultJailVEXPath
	}

	findings := make([]*triage.TriageFinding, 0, len(resp.Vex.Statements))
	for _, s := range resp.Vex.Statements {
		justification := s.Justification
		if justification == "" {
			justification = jailFallbackJustification
		}
		status := s.Status
		if status == "" {
			status = "affected"
		}
		findings = append(findings, &triage.TriageFinding{
			CVEID:          s.VulnID,
			Package:        s.Package,
			Ecosystem:      s.Ecosystem,
			InstalledVer:   s.InstalledVersion,
			FixedVer:       s.FixedVersion,
			Status:         status,
			Justification:  justification,
			ActionResponse: s.ActionStatement,
			Severity:       s.Severity,
		})
	}

	var (
		doc []byte
		err error
	)
	switch format {
	case "cyclonedx", "cyclonedx-json":
		doc, err = triage.GenerateCDXVEX(findings, "1.6")
	default:
		doc, err = triage.GenerateOpenVEX(findings, triage.OpenVEXOptions{
			ID:      resp.Vex.DocumentID,
			Author:  resp.Vex.Author,
			Tooling: "vulnetix-cli jail",
		})
	}
	if err != nil {
		return "", fmt.Errorf("render jail VEX: %w", err)
	}

	if err := writeJailArtifact(path, doc); err != nil {
		return "", err
	}
	return path, nil
}

// writeJailSARIF renders the non-vulnerability breaches — EOL, GOAL, HYGIENE —
// and returns the path written.
//
// Written to disk only. It is deliberately NOT posted to /v2/cli.<category>: the
// server records a ScannerRun and an IngestionSnapshot on any SARIF body it
// receives, so a jail that published its own findings would manufacture the very
// coverage the next jail run measures freshness against. The gate would report
// fresh forever and staleness could never fire again.
func writeJailSARIF(resp *vdb.CliJailResponse, path string) (string, error) {
	if resp == nil || resp.Sarif == nil || len(resp.Sarif.Results) == 0 {
		return "", nil
	}
	if path == "" {
		path = defaultJailSARIFPath
	}

	rules := make([]sast.RuleMetadata, 0, len(resp.Sarif.Rules))
	for _, r := range resp.Sarif.Rules {
		rules = append(rules, sast.RuleMetadata{
			ID:          r.ID,
			Name:        r.Name,
			Description: r.Description,
			HelpURI:     r.HelpURI,
			Severity:    r.Severity,
			Level:       r.Level,
			Tags:        r.Tags,
		})
	}

	findings := make([]sast.Finding, 0, len(resp.Sarif.Results))
	for _, f := range resp.Sarif.Results {
		findings = append(findings, sast.Finding{
			RuleID:      f.RuleID,
			Message:     f.Message,
			ArtifactURI: f.ArtifactURI,
			Severity:    f.Severity,
			Level:       f.Level,
			StartLine:   f.StartLine,
		})
	}

	doc := sast.BuildSARIF(findings, rules, version)
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("render jail SARIF: %w", err)
	}
	if err := writeJailArtifact(path, body); err != nil {
		return "", err
	}
	return path, nil
}

func writeJailArtifact(path string, body []byte) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
