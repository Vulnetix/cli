package sast

// RuleMetadata is unmarshaled from the Rego "metadata" constant object.
// Every field maps directly to the JSON keys used in the Rego policy.
type RuleMetadata struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	HelpURI     string   `json:"help_uri"`
	Languages   []string `json:"languages"`
	Severity    string   `json:"severity"`
	Level       string   `json:"level"`
	Kind        string   `json:"kind"`
	CWE         []int    `json:"cwe"`
	CAPEC       []string `json:"capec"`
	ATTACKTech  []string `json:"attack_technique"`
	CVSSv4      string   `json:"cvssv4"`
	CWSS        string   `json:"cwss"`
	Tags        []string `json:"tags"`
}

// Finding is unmarshaled from each element of the Rego "findings" set.
// Detection fields (ArtifactURI, StartLine, Snippet) are set by Rego logic.
// Fingerprint and Metadata are set by the engine after evaluation.
type Finding struct {
	RuleID      string `json:"rule_id"`
	Message     string `json:"message"`
	ArtifactURI string `json:"artifact_uri"`
	Severity    string `json:"severity"`
	Level       string `json:"level"`
	StartLine   int    `json:"start_line"`
	Snippet     string `json:"snippet"`
	Fingerprint string `json:"-"`
	Metadata    *RuleMetadata `json:"-"`
}

// SeverityToLevel maps severity to the default SARIF level when a rule
// doesn't explicitly set "level" in its metadata.
var SeverityToLevel = map[string]string{
	"critical": "error",
	"high":     "error",
	"medium":   "warning",
	"low":      "note",
	"info":     "note",
}

// SeverityLabel maps severity to the human-readable semantic label.
var SeverityLabel = map[string]string{
	"critical": "Dangerous",
	"high":     "Risky",
	"medium":   "Quality",
	"low":      "Style",
	"info":     "Tentative",
}

// EffectiveLevel returns the SARIF level for a rule — the explicit level
// if set, otherwise derived from severity.
func (m *RuleMetadata) EffectiveLevel() string {
	if m.Level != "" {
		return m.Level
	}
	if lvl, ok := SeverityToLevel[m.Severity]; ok {
		return lvl
	}
	return "warning"
}
