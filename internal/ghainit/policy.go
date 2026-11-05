// Package ghainit writes a repository's managed Vulnetix workflow from what the
// repository is made of and a small policy file. The workflow uses the granular
// actions: one or two languages or package managers get parallel jobs plus a
// rest step, three or more get the high-level scanner.
package ghainit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/vulnetix/cli/v4/internal/sast"
	"github.com/vulnetix/cli/v4/internal/scan"
)

// PolicyPath is the policy file, relative to the repository root.
const PolicyPath = ".vulnetix/workflow.yaml"

// WorkflowPath is the file `gha init` manages.
const WorkflowPath = ".github/workflows/vulnetix.yml"

// Trigger models. Each maps to the `on:` and job conditions of one kind of repo.
const (
	// TriggerPR scans pull requests and pushes to main.
	TriggerPR = "pr"
	// TriggerPush scans pushes to main.
	TriggerPush = "push"
	// TriggerBelai scans pushes to main and pull requests from belai/ branches.
	TriggerBelai = "belai"
)

// Selection picks scoped legs: "auto", "high", "none", or the names to run.
type Selection struct {
	Mode  string
	Names []string
}

// UnmarshalYAML reads a word or a list.
func (s *Selection) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.SequenceNode {
		return n.Decode(&s.Names)
	}
	return n.Decode(&s.Mode)
}

// Extra is one catalogue action run as its own job.
type Extra struct {
	Action string            `yaml:"action"`
	ID     string            `yaml:"id,omitempty"`
	With   map[string]string `yaml:"with,omitempty"`
	// Prior are catalogue actions run first in the same job, for an action that
	// reads what they write (report after sca, bom-validate after sbom).
	Prior []string `yaml:"prior,omitempty"`
	// Run are shell lines run before the action.
	Run []string `yaml:"run,omitempty"`
	// Then are shell lines run after the action, to check what it left behind.
	Then []string `yaml:"then,omitempty"`
	// Needs names a job whose SBOM or results this one reads.
	Needs string `yaml:"needs,omitempty"`
	// Permissions are added to the job's contents: read.
	Permissions map[string]string `yaml:"permissions,omitempty"`
}

// Policy is .vulnetix/workflow.yaml.
type Policy struct {
	Version  int    `yaml:"version"`
	Triggers string `yaml:"triggers"`
	// Runner is the self-hosted pool's label. Empty uses ubuntu-latest everywhere.
	Runner string `yaml:"runner,omitempty"`
	// Publish uploads SARIF to code scanning. Code scanning returns 403 on a
	// private repository without Code Security, so private repositories leave it off.
	Publish bool `yaml:"publish,omitempty"`

	SAST Selection `yaml:"sast"`
	SCA  Selection `yaml:"sca"`
	// NoRest leaves out the rest step, for a fixture whose legs are every
	// language it has. Without the step a finding outside the legs goes unseen.
	NoRest bool `yaml:"no_rest,omitempty"`

	Secrets    *bool  `yaml:"secrets,omitempty"`
	SBOM       *bool  `yaml:"sbom,omitempty"`
	IaC        string `yaml:"iac,omitempty"`        // auto, on, off
	Containers string `yaml:"containers,omitempty"` // auto, on, off
	License    bool   `yaml:"license,omitempty"`
	Malscan    bool   `yaml:"malscan,omitempty"`
	CBOM       bool   `yaml:"cbom,omitempty"`
	AIBOM      bool   `yaml:"aibom,omitempty"`
	Analyze    bool   `yaml:"analyze,omitempty"`

	// Gates maps a scanner to its --fail-on. A scanner with no gate reports and
	// never fails the job. There is no baseline, so a gate goes on once a run is
	// clean at that level.
	Gates map[string]string `yaml:"gates,omitempty"`
	// Rules are external rule packs per scanner: sast, secrets, iac, sast/go.
	Rules map[string][]string `yaml:"rules,omitempty"`

	// TEA publishes each run's BOMs to the Transparency Exchange API. Nil is on.
	TEA *TEA `yaml:"tea,omitempty"`

	Extras []Extra `yaml:"extras,omitempty"`
}

// TEA configures the publish job.
type TEA struct {
	Off        bool     `yaml:"off,omitempty"`
	Visibility string   `yaml:"visibility,omitempty"`
	Channels   []string `yaml:"channels,omitempty"`
}

// DefaultPolicy is a policy with nothing decided.
func DefaultPolicy() *Policy {
	return &Policy{Version: 1, Triggers: TriggerPush, Runner: "vulnetix-local",
		SAST: Selection{Mode: "auto"}, SCA: Selection{Mode: "auto"}, IaC: "auto", Containers: "auto"}
}

// LoadPolicy reads root's policy, or nil when it has none.
func LoadPolicy(root string) (*Policy, error) {
	raw, err := os.ReadFile(filepath.Join(root, PolicyPath))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p := DefaultPolicy()
	if err := yaml.Unmarshal(raw, p); err != nil {
		return nil, fmt.Errorf("%s: %w", PolicyPath, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", PolicyPath, err)
	}
	return p, nil
}

var (
	runnerLabel = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	actionPath  = regexp.MustCompile(`^(\.|[a-z0-9]+(-[a-z0-9]+)*(/[a-z0-9]+(-[a-z0-9]+)*)?)$`)
	jobID       = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// Validate refuses what would render a broken or unsafe workflow: a value that
// ends up in an expression, a runner label or a uses: line.
func (p *Policy) Validate() error {
	switch p.Triggers {
	case TriggerPR, TriggerPush, TriggerBelai:
	default:
		return fmt.Errorf("triggers must be pr, push or belai, got %q", p.Triggers)
	}
	if p.Runner != "" && !runnerLabel.MatchString(p.Runner) {
		return fmt.Errorf("runner %q is not a runner label", p.Runner)
	}
	langs := append(sast.ScopeLanguages(), "typescript")
	for _, n := range p.SAST.Names {
		if !slices.Contains(langs, n) {
			return fmt.Errorf("sast: unknown language %q", n)
		}
	}
	managers := scan.PackageManagers()
	for _, n := range p.SCA.Names {
		if !slices.Contains(managers, n) {
			return fmt.Errorf("sca: unknown package manager %q", n)
		}
	}
	for _, e := range p.Extras {
		if !actionPath.MatchString(e.Action) {
			return fmt.Errorf("extras: %q is not an action", e.Action)
		}
		if e.ID != "" && !jobID.MatchString(e.ID) {
			return fmt.Errorf("extras: %q is not a job id", e.ID)
		}
		for _, a := range e.Prior {
			if !actionPath.MatchString(a) {
				return fmt.Errorf("extras: prior %q is not an action", a)
			}
		}
		if e.Needs != "" && !jobID.MatchString(strings.Trim(e.Needs, "[], ")) && !strings.Contains(e.Needs, ",") {
			return fmt.Errorf("extras: needs %q is not a job id", e.Needs)
		}
	}
	return nil
}

func on(b *bool) bool { return b == nil || *b }
