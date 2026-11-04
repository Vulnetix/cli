package cdx

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
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
func NormalizeForSchema(b *BOM) {
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

// cycloneSetProperty is the library's property upsert, named so the bulk
// helpers in this package read as what they are.
func cycloneSetProperty(props []Property, name, value string) []Property {
	return cyclonedx.SetProperty(props, name, value)
}

// MarshalValidated serialises the document and validates it against the
// CycloneDX schema for its spec version. Unlike the library builders, which stop
// at the first violation, it reports every violation with its JSON pointer and,
// where the pointer lands on something the caller supplied, which flag or file
// to look at. A document customised from several sources fails for several
// reasons at once, and a reader fixing one at a time has no way to know how
// many are left.
func MarshalValidated(doc *BOM) ([]byte, error) {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal cyclonedx: %w", err)
	}
	_, violations, err := cyclonedx.ValidateCycloneDX(data)
	if err != nil {
		return nil, err
	}
	if len(violations) == 0 {
		return data, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "CycloneDX %s validation failed (%d violation(s)):", doc.SpecVersion, len(violations))
	for _, v := range violations {
		fmt.Fprintf(&b, "\n  %s: %s", v.Path, v.Message)
		if hint := violationHint(v.Path); hint != "" {
			fmt.Fprintf(&b, " (%s)", hint)
		}
	}
	return nil, errors.New(b.String())
}

// violationHint names the input most likely to have put a value at path.
func violationHint(path string) string {
	hints := []struct{ prefix, hint string }{
		{"/metadata/authors", "set by --bom-author, VULNETIX_BOM_AUTHORS or an overlay"},
		{"/metadata/supplier", "set by --bom-supplier or an overlay"},
		{"/metadata/manufacturer", "set by --bom-manufacturer or an overlay"},
		{"/metadata/licenses", "set by --bom-license or an overlay"},
		{"/metadata/properties", "set by --bom-property or an overlay"},
		{"/metadata/component", "set by --component-* or an overlay"},
		{"/metadata/lifecycles", "set by --lifecycle or an overlay"},
		{"/serialNumber", "set by --bom-serial or an overlay"},
		{"/version", "set by --bom-version or an overlay"},
		{"/services", "from an overlay"},
		{"/compositions", "from an overlay"},
		{"/annotations", "from an overlay"},
		{"/formulation", "from an overlay"},
		{"/declarations", "from an overlay"},
		{"/definitions", "from an overlay"},
		{"/externalReferences", "from an overlay"},
		{"/properties", "from an overlay"},
	}
	for _, h := range hints {
		if path == h.prefix || strings.HasPrefix(path, h.prefix+"/") {
			return h.hint
		}
	}
	return ""
}
