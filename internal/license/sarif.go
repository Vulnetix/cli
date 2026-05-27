package license

// SARIF adapter for license findings. Converts the analysis result into the
// same SARIF 2.1.0 shape the SAST engine uses (cli/internal/sast/sarif.go) so
// /v2/cli.license can ingest license-policy violations through the unified
// SARIFInfo + SarifResults persistence path.

import "fmt"

// SARIFFinding mirrors sast.Finding (kept local so this package does not
// depend on internal/sast). The cmd layer converts these into the typed
// vdb.CliSARIFFinding shape before posting.
type SARIFFinding struct {
	RuleID      string
	RuleName    string
	Message     string
	Severity    string
	Level       string
	ArtifactURI string
	PackagePurl string
	Fingerprint string
	Tags        []string
}

// SARIFRule mirrors sast.RuleMetadata's relevant fields.
type SARIFRule struct {
	ID       string
	Name     string
	Severity string
	Tags     []string
}

// BuildSARIFFromAnalysis converts the analysis result into SARIFFinding +
// SARIFRule slices. Each LicenseConflict becomes a finding with a rule id like
// "license-conflict-incompatible". Findings ([]license.Finding) become rules
// like "license-policy-{category}" carrying the package PURL and severity.
func BuildSARIFFromAnalysis(result *AnalysisResult) ([]SARIFFinding, []SARIFRule) {
	if result == nil {
		return nil, nil
	}
	rules := make([]SARIFRule, 0, 8)
	rulesByID := make(map[string]bool, 8)

	addRule := func(id, name, severity string, tags []string) {
		if rulesByID[id] {
			return
		}
		rulesByID[id] = true
		rules = append(rules, SARIFRule{ID: id, Name: name, Severity: severity, Tags: tags})
	}

	findings := make([]SARIFFinding, 0, len(result.Conflicts)+len(result.Findings))

	// Conflicts → "license-conflict-{type}" rules.
	for _, c := range result.Conflicts {
		ruleID := fmt.Sprintf("license-conflict-%s", normaliseSarifRuleSuffix(c.Type))
		addRule(ruleID, fmt.Sprintf("License conflict: %s", c.Type), c.Severity, []string{"license", "conflict", c.Type})
		findings = append(findings, SARIFFinding{
			RuleID:      ruleID,
			RuleName:    ruleID,
			Message:     fmt.Sprintf("%s vs %s (%s vs %s): %s", c.Package1, c.Package2, c.License1, c.License2, c.Description),
			Severity:    c.Severity,
			Level:       severityToSARIFLevel(c.Severity),
			ArtifactURI: c.Package1,
			PackagePurl: c.Package1,
			Fingerprint: fingerprint(c.Type, c.License1, c.License2, c.Package1, c.Package2),
			Tags:        []string{"license", "conflict"},
		})
	}

	// Per-finding rule violations (deprecated licenses, unknown, AGPL contaminants).
	for _, f := range result.Findings {
		ruleID := fmt.Sprintf("license-policy-%s", normaliseSarifRuleSuffix(f.Category))
		addRule(ruleID, f.Title, f.Severity, []string{"license", "policy", f.Category})
		purl := ""
		if f.Package.PackageName != "" {
			purl = fmt.Sprintf("pkg:%s/%s@%s", f.Package.Ecosystem, f.Package.PackageName, f.Package.PackageVersion)
		}
		findings = append(findings, SARIFFinding{
			RuleID:      ruleID,
			RuleName:    f.Title,
			Message:     f.Description,
			Severity:    f.Severity,
			Level:       severityToSARIFLevel(f.Severity),
			ArtifactURI: f.Package.SourceFile,
			PackagePurl: purl,
			Fingerprint: fingerprint(f.ID, f.Package.PackageName, f.Package.PackageVersion),
			Tags:        []string{"license", "policy", f.Category},
		})
	}

	return findings, rules
}

func severityToSARIFLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func normaliseSarifRuleSuffix(s string) string {
	if s == "" {
		return "unspecified"
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r+32)
		case r == ' ', r == '_', r == '.', r == '/':
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "unspecified"
	}
	return string(out)
}

func fingerprint(parts ...string) string {
	// Plain stable joiner — collisions are fine; server dedups on
	// (reportId, guid) which is unique per row by uuid.New().
	return joinParts(parts, "|")
}

func joinParts(parts []string, sep string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += sep + p
	}
	return out
}
