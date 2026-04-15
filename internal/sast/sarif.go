package sast

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// SARIF 2.1.0 types — manual struct marshaling (same approach as internal/cdx/).

// SARIFLog is the top-level SARIF document.
type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run.
type SARIFRun struct {
	Tool      SARIFTool      `json:"tool"`
	Results   []SARIFResult  `json:"results"`
	Artifacts []SARIFArtifact `json:"artifacts,omitempty"`
}

// SARIFTool describes the analysis tool.
type SARIFTool struct {
	Driver SARIFToolDriver `json:"driver"`
}

// SARIFToolDriver describes the primary analysis tool component.
type SARIFToolDriver struct {
	Name            string                     `json:"name"`
	Version         string                     `json:"version,omitempty"`
	InformationURI  string                     `json:"informationUri,omitempty"`
	Rules           []SARIFReportingDescriptor `json:"rules,omitempty"`
}

// SARIFReportingDescriptor describes a rule.
type SARIFReportingDescriptor struct {
	ID               string          `json:"id"`
	Name             string          `json:"name,omitempty"`
	ShortDescription *SARIFMessage   `json:"shortDescription,omitempty"`
	HelpURI          string          `json:"helpUri,omitempty"`
	Properties       SARIFPropertyBag `json:"properties,omitempty"`
}

// SARIFMessage is a SARIF message object.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFResult represents a single finding.
type SARIFResult struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level,omitempty"`
	Kind         string            `json:"kind,omitempty"`
	Message      SARIFMessage      `json:"message"`
	Locations    []SARIFLocation   `json:"locations,omitempty"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
	Properties   SARIFPropertyBag  `json:"properties,omitempty"`
}

// SARIFLocation describes where a result was found.
type SARIFLocation struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
}

// SARIFPhysicalLocation identifies a file and region.
type SARIFPhysicalLocation struct {
	ArtifactLocation *SARIFArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *SARIFRegion           `json:"region,omitempty"`
}

// SARIFArtifactLocation is a URI reference to an artifact.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion identifies a portion of an artifact.
type SARIFRegion struct {
	StartLine int           `json:"startLine,omitempty"`
	Snippet   *SARIFSnippet `json:"snippet,omitempty"`
}

// SARIFSnippet holds a text snippet from the source.
type SARIFSnippet struct {
	Text string `json:"text"`
}

// SARIFArtifact describes an artifact referenced by results.
type SARIFArtifact struct {
	Location *SARIFArtifactLocation `json:"location,omitempty"`
}

// SARIFPropertyBag is a property bag for extensible metadata.
type SARIFPropertyBag map[string]any

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
		if f.Metadata != nil {
			result.Kind = f.Metadata.Kind
		}

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
