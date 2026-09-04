package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/vulnetix/cli/v3/internal/fix"
)

// PolicyFile is where a repository states what its agents may do without being
// interrupted.
const PolicyFile = ".vulnetix/agent.yaml"

// Signal is one reason a guard might speak up. Naming them lets a repository
// tune the guard without the guard growing a flag per condition.
type Signal string

const (
	// SignalMalware is a package a malware feed has named. A version bump is
	// not a fix for it, so it is the one signal that blocks by default.
	SignalMalware Signal = "malware"
	// SignalKEVCritical is a critical advisory that is also on a known-exploited
	// list. Proceeding is never the right call without a decision being made.
	SignalKEVCritical Signal = "kev-critical"
	// SignalSeverityHigh is a high-or-worse advisory with no exploitation
	// evidence.
	SignalSeverityHigh Signal = "severity-high"
	// SignalBelowTarget means a safer version exists under the configured
	// strategy. This is the ordinary case and only ever warns.
	SignalBelowTarget Signal = "below-target"
	// SignalEOL is a package past its end of life, where no fix is coming.
	SignalEOL Signal = "eol"
	// SignalUnpinned is a direct dependency added with a range rather than an
	// exact version.
	SignalUnpinned Signal = "unpinned"
	// SignalCooldown is a version published very recently, before the ecosystem
	// has had a chance to notice anything wrong with it.
	SignalCooldown Signal = "cooldown"
	// SignalSecret is a credential in a change about to be recorded.
	SignalSecret Signal = "secret"
)

// GuardPolicy says which signals block and which merely inform.
//
// A signal in neither list is silent. That default matters: a signal this
// version of the CLI has not heard of should not start interrupting people
// because a newer server began reporting it.
type GuardPolicy struct {
	Block []Signal `yaml:"block"`
	Warn  []Signal `yaml:"warn"`
}

// Decide maps a signal onto what to do about it.
func (g GuardPolicy) Decide(s Signal) Decision {
	for _, b := range g.Block {
		if b == s {
			return Block
		}
	}
	for _, w := range g.Warn {
		if w == s {
			return Inform
		}
	}
	return Silent
}

// Policy is the whole agent-surface configuration for one repository.
type Policy struct {
	// SafeHarbourStrategy picks which safe version counts as the target.
	//
	// Defaults to safest rather than the CLI's stable, matching the editor. An
	// agent adding a dependency on its own initiative gets less deliberation
	// than a version someone typed, so the default prefers the smallest risk
	// over the smallest change.
	SafeHarbourStrategy fix.Strategy `yaml:"safeHarbourStrategy"`

	// MaxMajorBump caps how far a recommendation may travel. Zero refuses major
	// versions, which are almost always a code change rather than a version
	// change.
	MaxMajorBump int `yaml:"maxMajorBump"`

	// CooldownDays is the age below which a version is considered too new to
	// trust. Zero disables the check.
	CooldownDays int `yaml:"cooldownDays"`

	DependencyGuard GuardPolicy `yaml:"dependencyGuard"`
	ChangeGuard     GuardPolicy `yaml:"changeGuard"`

	// Enabled turns the whole surface off without uninstalling it.
	Enabled *bool `yaml:"enabled"`
}

type policyDocument struct {
	Agent Policy `yaml:"agent"`
}

// DefaultPolicy blocks only what is never the right call and warns about the
// rest.
//
// The split is the design: proceeding with a known-malicious package or a
// critical advisory that is being exploited in the wild is not a trade-off
// anyone makes deliberately, so those stop. Everything else is information the
// agent can weigh, and interrupting for it would train people to ignore the
// interruption.
func DefaultPolicy() Policy {
	return Policy{
		SafeHarbourStrategy: fix.StrategySafest,
		MaxMajorBump:        0,
		CooldownDays:        0,
		DependencyGuard: GuardPolicy{
			Block: []Signal{SignalMalware, SignalKEVCritical},
			// Unpinned is deliberately not here. `npm i axios` is how almost
			// every install is written, and npm records a range by default, so
			// warning on it fires on nearly every command and teaches people to
			// stop reading. A repository that wants exact pins has --block-unpinned
			// on the scan family, which is where a build-time policy belongs.
			Warn: []Signal{SignalSeverityHigh, SignalBelowTarget, SignalEOL, SignalCooldown},
		},
		ChangeGuard: GuardPolicy{
			Block: []Signal{SignalSecret},
			Warn:  []Signal{SignalSeverityHigh, SignalKEVCritical},
		},
	}
}

// Active reports whether the surface is switched on.
func (p Policy) Active() bool { return p.Enabled == nil || *p.Enabled }

// LoadPolicy reads the repository's policy, falling back to the default.
//
// A missing file is the normal case and yields the default. A malformed file is
// reported, because silently guarding on something other than what someone
// wrote is worse than saying the file is broken.
func LoadPolicy(root string) (Policy, error) {
	path := filepath.Join(root, filepath.FromSlash(PolicyFile))
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultPolicy(), nil
		}
		return DefaultPolicy(), fmt.Errorf("reading %s: %w", PolicyFile, err)
	}

	var doc policyDocument
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return DefaultPolicy(), fmt.Errorf("parsing %s: %w", PolicyFile, err)
	}

	return doc.Agent.withDefaults(), nil
}

// withDefaults fills in what the file left unset.
//
// An omitted guard section inherits the default rather than becoming empty: a
// file that sets only the strategy should not silently switch the malware block
// off.
func (p Policy) withDefaults() Policy {
	d := DefaultPolicy()

	switch strings.ToLower(string(p.SafeHarbourStrategy)) {
	case string(fix.StrategyLatest):
		p.SafeHarbourStrategy = fix.StrategyLatest
	case string(fix.StrategyStable):
		p.SafeHarbourStrategy = fix.StrategyStable
	case string(fix.StrategySafest):
		p.SafeHarbourStrategy = fix.StrategySafest
	default:
		p.SafeHarbourStrategy = d.SafeHarbourStrategy
	}

	if p.MaxMajorBump < 0 {
		p.MaxMajorBump = d.MaxMajorBump
	}
	if p.CooldownDays < 0 {
		p.CooldownDays = 0
	}
	if len(p.DependencyGuard.Block) == 0 && len(p.DependencyGuard.Warn) == 0 {
		p.DependencyGuard = d.DependencyGuard
	}
	if len(p.ChangeGuard.Block) == 0 && len(p.ChangeGuard.Warn) == 0 {
		p.ChangeGuard = d.ChangeGuard
	}
	return p
}
