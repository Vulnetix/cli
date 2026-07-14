package aifirewall

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Baseline is the recommended guardrail set — PII masking, prompt injection, and
// so on. It is supplied by the server, not shipped in the binary, so the
// recommendations can improve without a CLI release. It never contains provider
// or model allow/deny lists: what an org is permitted to call is the org's
// decision, not a default we push.
type Baseline struct {
	Version    string              `json:"version" yaml:"version"`
	Ref        string              `json:"ref" yaml:"ref"`
	Guardrails []BaselineGuardrail `json:"guardrails" yaml:"guardrails"`
}

// BaselineGuardrail is one recommended rule. The enums are identical to a
// guardrail's, so a baseline entry applies through the ordinary guardrail write
// path with no special casing.
type BaselineGuardrail struct {
	ID          string   `json:"id" yaml:"id"` // stable; the key for excludes
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description" yaml:"description"`
	RuleType    string   `json:"ruleType" yaml:"ruleType"`
	Action      string   `json:"action" yaml:"action"`
	Pattern     string   `json:"pattern" yaml:"pattern"`
	Priority    int      `json:"priority" yaml:"priority"`
	Enabled     bool     `json:"enabled" yaml:"enabled"`
	Tags        []string `json:"tags" yaml:"tags"`
	Severity    string   `json:"severity" yaml:"severity"`
}

// Compile validates every entry. The whole baseline is rejected on a single bad
// pattern rather than applied in part: half a security baseline, silently, is
// worse than none — the org would believe it had the full set.
func (b *Baseline) Compile() error {
	seen := map[string]bool{}
	for i, g := range b.Guardrails {
		if g.ID == "" {
			return fmt.Errorf("baseline guardrail %d: id is required (it is the key for excludes)", i)
		}
		if seen[g.ID] {
			return fmt.Errorf("baseline guardrail %q: duplicate id", g.ID)
		}
		seen[g.ID] = true
		if g.Name == "" {
			return fmt.Errorf("baseline guardrail %q: name is required", g.ID)
		}
		if err := ValidateGuardrail(g.Name, g.RuleType, g.Action, g.Pattern); err != nil {
			return fmt.Errorf("baseline %q: %w", g.ID, err)
		}
	}
	return nil
}

// LoadBaselineFile reads a baseline from a local JSON or YAML file (--catalog),
// which replaces the server's set entirely.
func LoadBaselineFile(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Baseline
	if strings.HasSuffix(path, ".json") {
		if err := json.Unmarshal(data, &b); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	} else if err := yaml.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := b.Compile(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if b.Ref == "" {
		b.Ref = "local"
	}
	return &b, nil
}

// ComposeGuardrails merges the baseline into the file's own guardrails.
//
// A local guardrail with the same name always wins — the file is the org's
// considered position, the baseline is a recommendation. Excluded ids are
// dropped. The result is the desired guardrail set.
func ComposeGuardrails(spec []GuardrailSpec, baseline *Baseline, exclude []string) []GuardrailSpec {
	if baseline == nil {
		return spec
	}
	excluded := map[string]bool{}
	for _, id := range exclude {
		excluded[id] = true
	}
	local := map[string]bool{}
	for _, g := range spec {
		local[g.Name] = true
	}

	out := append([]GuardrailSpec{}, spec...)
	for _, bg := range baseline.Guardrails {
		if excluded[bg.ID] || local[bg.Name] {
			continue
		}
		enabled := bg.Enabled
		out = append(out, GuardrailSpec{
			Name:       bg.Name,
			BaselineID: bg.ID,
			RuleType:   bg.RuleType,
			Action:     bg.Action,
			Pattern:    bg.Pattern,
			Priority:   bg.Priority,
			Enabled:    &enabled,
		})
	}
	return out
}
