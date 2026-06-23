package cdx

import (
	"slices"
	"strings"
)

// cdxSeverities is the CycloneDX rating severity enum.
var cdxSeverities = map[string]bool{
	"critical": true, "high": true, "medium": true,
	"low": true, "info": true, "none": true, "unknown": true,
}

// cdxJustifications is the CycloneDX impactAnalysisJustification enum. Note that
// these are the ONLY legal analysis.justification values — remediation verbs
// like "update" belong in analysis.response, not here.
var cdxJustifications = map[string]bool{
	"code_not_present": true, "code_not_reachable": true,
	"requires_configuration": true, "requires_dependency": true,
	"requires_environment": true, "protected_by_compiler": true,
	"protected_at_runtime": true, "protected_at_perimeter": true,
	"protected_by_mitigating_control": true,
}

// normalizeCDXSeverity maps an internal severity onto the CycloneDX severity
// enum. Empty is preserved (the field is omitempty); unrecognised internal
// values such as "unscored" collapse to "unknown".
func normalizeCDXSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || cdxSeverities[s] {
		return s
	}
	return "unknown"
}

// NormalizeForSchema heals enum values the CycloneDX schema would reject, so the
// BOM validates regardless of whether a value was freshly generated or carried
// forward from an older on-disk SBOM during a merge (mergeVulnerabilities keeps
// existing entries verbatim, so legacy bad values would otherwise persist across
// rescans). It fixes the two known classes seen in the wild:
//
//   - rating.severity: internal values like "unscored" → "unknown".
//   - analysis.justification: a legacy "update" (a response value, not a
//     justification) is recovered into analysis.response; any other invalid
//     justification is dropped.
//
// It is applied at every BOM output path; anything it does not recognise is left
// untouched so the write-time validation guard still catches new bug classes.
func (b *BOM) NormalizeForSchema() {
	for i := range b.Vulnerabilities {
		v := &b.Vulnerabilities[i]
		for j := range v.Ratings {
			v.Ratings[j].Severity = normalizeCDXSeverity(v.Ratings[j].Severity)
		}
		a := v.Analysis
		if a != nil && a.Justification != "" && !cdxJustifications[a.Justification] {
			if a.Justification == "update" && !slices.Contains(a.Response, "update") {
				a.Response = append(a.Response, "update")
			}
			a.Justification = ""
		}
	}
}
