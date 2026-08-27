package sast

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Vulnetix/vdb-sca-match/sarif"
)

// SARIF 2.1.0 types now live in the shared module
// github.com/Vulnetix/vdb-sca-match/sarif, so the CLI and vdb-api parse, write
// and decompose SARIF through one implementation. These aliases keep the ~40
// existing `sast.SARIF*` call sites compiling unchanged.
//
// Note the shared model is a read-side superset of what this file used to
// declare: it adds ruleIndex, suppressions, partialFingerprints, taxonomies,
// tool extensions and result guids, none of which the writer emits but all of
// which third-party documents rely on.

type (
	SARIFLog                 = sarif.Log
	SARIFRun                 = sarif.Run
	SARIFInvocation          = sarif.Invocation
	SARIFNotification        = sarif.Notification
	SARIFTool                = sarif.Tool
	SARIFToolDriver          = sarif.ToolComponent
	SARIFReportingDescriptor = sarif.ReportingDescriptor
	SARIFMessage             = sarif.Message
	SARIFResult              = sarif.Result
	SARIFLocation            = sarif.Location
	SARIFPhysicalLocation    = sarif.PhysicalLocation
	SARIFArtifactLocation    = sarif.ArtifactLocation
	SARIFRegion              = sarif.Region
	SARIFSnippet             = sarif.Snippet
	SARIFArtifact            = sarif.Artifact
	SARIFPropertyBag         = sarif.PropertyBag
)

// MarkConfidenceGap flags a result whose evidence could not be fully
// verified, with a reason stating exactly what was unverifiable and why.
func MarkConfidenceGap(res *SARIFResult, reason string) {
	if res == nil {
		return
	}
	if res.Properties == nil {
		res.Properties = SARIFPropertyBag{}
	}
	res.Properties["vulnetix/confidence-gap"] = true
	res.Properties["vulnetix/gap-reason"] = reason
}

// BuildSARIF converts findings and rules into a SARIF 2.1.0 log.
func BuildSARIF(findings []Finding, rules []RuleMetadata, toolVersion string) *SARIFLog {
	// Build rule descriptors.
	descriptors := make([]SARIFReportingDescriptor, 0, len(rules))
	for _, r := range rules {
		desc := SARIFReportingDescriptor{
			ID:   r.ID,
			Name: r.Name,
			ShortDescription: &SARIFMessage{
				Text: r.Description,
			},
			HelpURI: r.HelpURI,
			Properties: SARIFPropertyBag{
				"severity": r.Severity,
				"tags":     r.Tags,
			},
		}
		if len(r.CWE) > 0 {
			cweStrs := make([]string, len(r.CWE))
			for i, c := range r.CWE {
				cweStrs[i] = "CWE-" + strconv.Itoa(c)
			}
			desc.Properties["cwe"] = cweStrs
		}
		if len(r.CAPEC) > 0 {
			desc.Properties["capec"] = r.CAPEC
		}
		if len(r.ATTACKTech) > 0 {
			desc.Properties["attack_technique"] = r.ATTACKTech
		}
		if r.CVSSv4 != "" {
			desc.Properties["cvssv4"] = r.CVSSv4
		}
		if r.CWSS != "" {
			desc.Properties["cwss"] = r.CWSS
		}
		descriptors = append(descriptors, desc)
	}

	// Build results.
	results := make([]SARIFResult, 0, len(findings))
	for _, f := range findings {
		result := SARIFResult{
			RuleID:  f.RuleID,
			Level:   f.Level,
			Message: SARIFMessage{Text: f.Message},
		}
		// result.kind is a SARIF enum (notApplicable|pass|fail|review|open|
		// informational) and defaults to "fail", which is what a reported
		// finding is. The rule's Vulnetix kind — sast/secrets/iac/oci — is our
		// own taxonomy and was being written here, making every SARIF document
		// we emit fail schema validation on every result. It belongs in the
		// property bag, which is where the rest of our metadata already lives.
		// (Routing to /v2/cli.<kind> reads the rule metadata, never this field.)

		loc := SARIFLocation{
			PhysicalLocation: &SARIFPhysicalLocation{
				ArtifactLocation: &SARIFArtifactLocation{
					URI: f.ArtifactURI,
				},
			},
		}
		if f.StartLine > 0 {
			loc.PhysicalLocation.Region = &SARIFRegion{
				StartLine: f.StartLine,
			}
			if f.EndLine > f.StartLine {
				loc.PhysicalLocation.Region.EndLine = f.EndLine
			}
			if f.Snippet != "" {
				loc.PhysicalLocation.Region.Snippet = &SARIFSnippet{Text: f.Snippet}
			}
		}
		result.Locations = []SARIFLocation{loc}

		if f.Fingerprint != "" {
			result.Fingerprints = map[string]string{
				"vulnetix/v1": f.Fingerprint,
			}
		}

		result.Properties = SARIFPropertyBag{
			"severity": f.Severity,
		}
		if f.Metadata != nil && f.Metadata.Kind != "" {
			result.Properties["vulnetix/kind"] = f.Metadata.Kind
		}
		if f.IsTestSuite {
			result.Properties["vulnetix/test-suite"] = true
			if f.TestFramework != "" {
				result.Properties["vulnetix/test-framework"] = f.TestFramework
			}
			if f.TestLanguage != "" {
				result.Properties["vulnetix/test-language"] = f.TestLanguage
			}
			if f.TestConfidence != "" {
				result.Properties["vulnetix/test-confidence"] = f.TestConfidence
			}
			if f.TestMatchedPattern != "" {
				result.Properties["vulnetix/test-matched-pattern"] = f.TestMatchedPattern
			}
			if len(f.TestEvidence) > 0 {
				result.Properties["vulnetix/test-evidence"] = f.TestEvidence
			}
		}

		results = append(results, result)
	}

	return &SARIFLog{
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{{
			Tool: SARIFTool{
				Driver: SARIFToolDriver{
					Name:           "vulnetix",
					Version:        toolVersion,
					InformationURI: "https://vulnetix.com",
					Rules:          descriptors,
				},
			},
			Results: results,
		}},
	}
}

// WriteSARIF serializes a SARIF log to the given file path.
func WriteSARIF(log *SARIFLog, path string) error {
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sarif: %w", err)
	}
	// Ensure the parent (.vulnetix) exists — on a fresh --path target it may not
	// have been created yet when the SARIF is the first artefact written.
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create sarif dir: %w", err)
		}
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadExistingSARIF reads a SARIF log from disk. Returns nil if the file
// does not exist.
func LoadExistingSARIF(path string) (*SARIFLog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var log SARIFLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("parse sarif: %w", err)
	}
	return &log, nil
}

// ResolvedFingerprints returns fingerprints present in the old SARIF log
// but absent from the new findings. These represent resolved findings.
func ResolvedFingerprints(oldLog *SARIFLog, newFindings []Finding) []string {
	if oldLog == nil || len(oldLog.Runs) == 0 {
		return nil
	}

	// Collect current fingerprints.
	current := make(map[string]bool, len(newFindings))
	for _, f := range newFindings {
		if f.Fingerprint != "" {
			current[f.Fingerprint] = true
		}
	}

	// Find old fingerprints not in current set.
	var resolved []string
	for _, run := range oldLog.Runs {
		for _, result := range run.Results {
			for _, fp := range result.Fingerprints {
				if fp != "" && !current[fp] {
					resolved = append(resolved, fp)
				}
			}
		}
	}
	return resolved
}
