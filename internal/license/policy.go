package license

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// policy.go is the declarative form of "which licences are acceptable here".
//
// The flat allow list (--allow / --allow-file) answers that question one way:
// name every acceptable SPDX id. That works until the list is a hundred entries
// long and nobody can say why MPL-2.0 is on it and EPL-2.0 is not. A policy
// answers it by category instead — permissive is fine, network copyleft is a
// critical finding, unknown is a warning — which is how the decision is
// actually made, and which stays correct when a dependency introduces a licence
// nobody has enumerated yet.
//
// The allow list keeps working unchanged. A policy is the richer form for teams
// that need per-project thresholds and an auditable exception process; a flat
// list is the right answer for everyone else.

// PolicyAPIVersion is the apiVersion a policy document must declare.
const PolicyAPIVersion = "vulnetix.com/v1"

// PolicyKind is the kind a policy document must declare.
const PolicyKind = "LicensePolicy"

// UnknownHandling says what to do about a licence that could not be resolved.
type UnknownHandling string

const (
	// UnknownWarn reports unresolved licences without failing. The default: an
	// unresolved licence is a gap in the data, not evidence of a violation, and
	// failing on it would make the policy unusable on any real dependency tree.
	UnknownWarn UnknownHandling = "warn"
	// UnknownFail treats an unresolved licence as a violation. For teams whose
	// compliance position is that an unidentified licence cannot be shipped.
	UnknownFail UnknownHandling = "fail"
	// UnknownIgnore drops unresolved licences entirely.
	UnknownIgnore UnknownHandling = "ignore"
)

// ScopeHandling says how a dependency scope is treated.
type ScopeHandling string

const (
	// ScopeEvaluate applies the policy to this scope.
	ScopeEvaluate ScopeHandling = "evaluate"
	// ScopeIgnore skips it. Development and test dependencies are not
	// distributed, so a copyleft build tool is usually not a licence obligation.
	ScopeIgnore ScopeHandling = "ignore"
)

// Policy is a declarative licence policy.
type Policy struct {
	APIVersion string `yaml:"apiVersion" json:"apiVersion"`
	Kind       string `yaml:"kind" json:"kind"`

	// Categories reassigns SPDX ids to categories, overriding the embedded
	// classification. An organisation's counsel may classify a licence
	// differently from the default, and that decision belongs in their policy
	// rather than in a fork of this CLI.
	Categories map[Category][]string `yaml:"categories,omitempty" json:"categories,omitempty"`

	// Severity maps a category to the severity of a finding against it.
	Severity map[Category]string `yaml:"severity,omitempty" json:"severity,omitempty"`

	// Unknown says what to do about an unresolved licence.
	Unknown UnknownHandling `yaml:"unknown,omitempty" json:"unknown,omitempty"`

	// Scopes says how each dependency scope is treated.
	Scopes map[string]ScopeHandling `yaml:"scopes,omitempty" json:"scopes,omitempty"`

	// Projects holds per-project overrides, keyed on the --project label. A
	// monorepo's payment service and its docs site have different obligations,
	// and forcing them to share one threshold means the stricter one wins
	// everywhere or the looser one wins everywhere.
	Projects map[string]ProjectPolicy `yaml:"projects,omitempty" json:"projects,omitempty"`

	// categoryIndex is the compiled SPDX id → category override map.
	categoryIndex map[string]Category
}

// ProjectPolicy overrides parts of the policy for one project.
type ProjectPolicy struct {
	Severity map[Category]string      `yaml:"severity,omitempty" json:"severity,omitempty"`
	Unknown  UnknownHandling          `yaml:"unknown,omitempty" json:"unknown,omitempty"`
	Scopes   map[string]ScopeHandling `yaml:"scopes,omitempty" json:"scopes,omitempty"`
}

// DefaultPolicy is the policy applied when none is supplied.
//
// It reproduces exactly what the evaluator did before policies existed, so
// adopting a policy file is a change a team makes deliberately rather than one
// that arrives with an upgrade and turns their build red. Two consequences are
// deliberate and easy to get wrong:
//
//   - Only strong copyleft carries a severity. Proprietary arguably should too,
//     but it did not before, and quietly adding it would fail builds on an
//     upgrade for a decision nobody made.
//   - No scope is ignored. Scope filtering is genuinely useful — a copyleft
//     build tool that never ships is not a licence obligation — but turning it
//     on by default would silently stop reporting findings that were being
//     reported yesterday, which is the more dangerous direction to be wrong in.
//
// A policy file opts into both. RecommendedPolicy() is the starting point.
func DefaultPolicy() *Policy {
	p := &Policy{
		APIVersion: PolicyAPIVersion,
		Kind:       PolicyKind,
		Severity: map[Category]string{
			CategoryPermissive:     "none",
			CategoryPublicDomain:   "none",
			CategoryWeakCopyleft:   "none",
			CategoryStrongCopyleft: "high",
			CategoryProprietary:    "none",
			CategoryUnknown:        "medium",
		},
		Unknown: UnknownWarn,
		Scopes:  map[string]ScopeHandling{},
	}
	p.compile()
	return p
}

// RecommendedPolicy is the starting point `license policy init` writes.
//
// Unlike DefaultPolicy it makes the judgements a team adopting a policy
// generally wants: proprietary licences are a finding, network copyleft is
// critical because the obligation triggers on use rather than distribution, and
// dependencies that are never shipped are out of scope.
func RecommendedPolicy() *Policy {
	p := &Policy{
		APIVersion: PolicyAPIVersion,
		Kind:       PolicyKind,
		Severity: map[Category]string{
			CategoryPermissive:     "none",
			CategoryPublicDomain:   "none",
			CategoryWeakCopyleft:   "low",
			CategoryStrongCopyleft: "high",
			CategoryProprietary:    "high",
			CategoryUnknown:        "medium",
		},
		Unknown: UnknownWarn,
		Scopes: map[string]ScopeHandling{
			"development": ScopeIgnore,
			"dev":         ScopeIgnore,
			"test":        ScopeIgnore,
			"optional":    ScopeIgnore,
		},
		Categories: map[Category][]string{
			// AGPL's obligation triggers on network use, not distribution, so a
			// service that never ships a binary still incurs it. That makes it a
			// different risk from GPL, and the embedded database does not
			// separate them.
			CategoryStrongCopyleft: {"AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0"},
		},
	}
	p.compile()
	return p
}

// LoadPolicy reads a policy from a YAML file.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := ParsePolicy(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// ParsePolicy parses a policy document, filling defaults for absent fields.
func ParsePolicy(data []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}

	// Absent sections inherit the defaults rather than becoming empty. A policy
	// that only sets `severity` must not silently stop ignoring dev scopes.
	def := DefaultPolicy()
	if p.Unknown == "" {
		p.Unknown = def.Unknown
	}
	if p.Scopes == nil {
		p.Scopes = def.Scopes
	}
	if p.Severity == nil {
		p.Severity = def.Severity
	} else {
		for cat, sev := range def.Severity {
			if _, set := p.Severity[cat]; !set {
				p.Severity[cat] = sev
			}
		}
	}
	p.compile()
	return &p, nil
}

// Validate checks a policy document for structural problems.
func (p *Policy) Validate() error {
	if p.APIVersion != "" && p.APIVersion != PolicyAPIVersion {
		return fmt.Errorf("unsupported apiVersion %q (expected %s)", p.APIVersion, PolicyAPIVersion)
	}
	if p.Kind != "" && p.Kind != PolicyKind {
		return fmt.Errorf("unsupported kind %q (expected %s)", p.Kind, PolicyKind)
	}
	for cat := range p.Categories {
		if !validCategory(cat) {
			return fmt.Errorf("categories: unknown category %q", cat)
		}
	}
	for cat, sev := range p.Severity {
		if !validCategory(cat) {
			return fmt.Errorf("severity: unknown category %q", cat)
		}
		if !validSeverity(sev) {
			return fmt.Errorf("severity.%s: %q is not a severity (expected none, low, medium, high or critical)", cat, sev)
		}
	}
	switch p.Unknown {
	case "", UnknownWarn, UnknownFail, UnknownIgnore:
	default:
		return fmt.Errorf("unknown: %q (expected warn, fail or ignore)", p.Unknown)
	}
	for scope, handling := range p.Scopes {
		switch handling {
		case ScopeEvaluate, ScopeIgnore:
		default:
			return fmt.Errorf("scopes.%s: %q (expected evaluate or ignore)", scope, handling)
		}
	}
	for name, proj := range p.Projects {
		for cat, sev := range proj.Severity {
			if !validCategory(cat) {
				return fmt.Errorf("projects.%s.severity: unknown category %q", name, cat)
			}
			if !validSeverity(sev) {
				return fmt.Errorf("projects.%s.severity.%s: %q is not a severity", name, cat, sev)
			}
		}
	}
	return nil
}

// compile builds the SPDX id → category override index.
func (p *Policy) compile() {
	p.categoryIndex = map[string]Category{}
	for cat, ids := range p.Categories {
		for _, id := range ids {
			p.categoryIndex[strings.ToLower(NormalizeSPDX(id))] = cat
		}
	}
}

// CategoryFor returns the category for an SPDX id under this policy.
//
// A policy override wins over the embedded classification, which is the point:
// the embedded database is a reasonable default, not an authority on what a
// particular organisation has decided about a particular licence.
func (p *Policy) CategoryFor(spdxID string, fallback Category) Category {
	if p == nil {
		return fallback
	}
	if cat, ok := p.categoryIndex[strings.ToLower(spdxID)]; ok {
		return cat
	}
	if cat, ok := p.categoryIndex[strings.ToLower(NormalizeSPDX(spdxID))]; ok {
		return cat
	}
	return fallback
}

// SeverityFor returns the severity a category carries, honouring per-project
// overrides. An empty result means the category produces no finding.
func (p *Policy) SeverityFor(cat Category, project string) string {
	if p == nil {
		return ""
	}
	if proj, ok := p.Projects[project]; ok && project != "" {
		if sev, set := proj.Severity[cat]; set {
			return normaliseNone(sev)
		}
	}
	return normaliseNone(p.Severity[cat])
}

// UnknownFor returns the unknown-licence handling, honouring project overrides.
func (p *Policy) UnknownFor(project string) UnknownHandling {
	if p == nil {
		return UnknownWarn
	}
	if proj, ok := p.Projects[project]; ok && project != "" && proj.Unknown != "" {
		return proj.Unknown
	}
	if p.Unknown == "" {
		return UnknownWarn
	}
	return p.Unknown
}

// EvaluatesScope reports whether a dependency scope is in scope for the policy.
func (p *Policy) EvaluatesScope(scope, project string) bool {
	if p == nil || scope == "" {
		return true
	}
	key := strings.ToLower(scope)
	if proj, ok := p.Projects[project]; ok && project != "" {
		if handling, set := proj.Scopes[key]; set {
			return handling != ScopeIgnore
		}
	}
	return p.Scopes[key] != ScopeIgnore
}

// normaliseNone maps the "no finding" spelling onto the empty string, so
// callers have one thing to check.
func normaliseNone(sev string) string {
	if strings.EqualFold(sev, "none") {
		return ""
	}
	return strings.ToLower(sev)
}

func validCategory(c Category) bool {
	switch c {
	case CategoryPermissive, CategoryWeakCopyleft, CategoryStrongCopyleft,
		CategoryProprietary, CategoryPublicDomain, CategoryUnknown:
		return true
	}
	return false
}

func validSeverity(s string) bool {
	switch strings.ToLower(s) {
	case "none", "low", "medium", "high", "critical":
		return true
	}
	return false
}

// MarshalYAML renders the policy as a YAML document.
func (p *Policy) MarshalYAML() ([]byte, error) {
	if p.APIVersion == "" {
		p.APIVersion = PolicyAPIVersion
	}
	if p.Kind == "" {
		p.Kind = PolicyKind
	}
	return yaml.Marshal(p)
}
