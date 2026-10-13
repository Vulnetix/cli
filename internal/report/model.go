// Package report turns scan findings into what a person reads and what a
// pipeline greps.
//
// One Report, several renderers. The model is built once from the enriched
// findings, the dependency graphs, any defence lookups and any recorded
// compensating controls; the packages, findings, tree, plain and GitHub
// renderers all read it. A wording change lands everywhere at once, and the
// renderers cannot disagree about what a package's urgency or fix is, because
// neither is computed in a renderer.
//
// The unit is the package, not the advisory. Nobody upgrades an advisory: they
// upgrade a package, once, to a version that clears every advisory on it.
package report

import (
	"time"

	"github.com/vulnetix/cli/v3/internal/defences"
	"github.com/vulnetix/cli/v3/internal/scan"
)

// Group says what to do about a package, which is not the same as how severe it
// is. A critical advisory nothing reaches can wait; a medium one under active
// exploitation cannot.
type Group string

const (
	// GroupAction is exploited, reachable, on a KEV list or malicious.
	GroupAction Group = "action"
	// GroupWait is affected but with no signal that raises urgency.
	GroupWait Group = "wait"
	// GroupUnverified is matched by name where the advisory's range cannot be
	// compared with the installed version (a git commit, say). It still counts:
	// unknown is not safe. It does not claim urgency, because nobody has
	// established the package is affected at all.
	GroupUnverified Group = "unverified"
	// GroupProtected has an unexpired recorded control that blocks the request.
	// It is still affected, and still counted.
	GroupProtected Group = "protected"
	// GroupMonitored has an unexpired recorded control that only detects, or a
	// blocking rule still in log-only mode. It stops nothing.
	GroupMonitored Group = "monitored"
	// GroupNotAffected was matched by name and ruled out by version.
	GroupNotAffected Group = "not_affected"
)

// groupOrder is the order groups are printed in.
var groupOrder = []Group{GroupAction, GroupWait, GroupUnverified, GroupProtected, GroupMonitored, GroupNotAffected}

// Title is the group's heading.
func (g Group) Title() string {
	switch g {
	case GroupAction:
		return "NEEDS ACTION"
	case GroupWait:
		return "CAN WAIT"
	case GroupUnverified:
		return "UNVERIFIED"
	case GroupProtected:
		return "PROTECTED"
	case GroupMonitored:
		return "MONITORED"
	case GroupNotAffected:
		return "NOT AFFECTED"
	}
	return string(g)
}

// Signal is one fact that raises (or merely annotates) a finding's urgency.
type Signal struct {
	Label string
	// Strong signals move a package into GroupAction.
	Strong bool
}

// Advisory is one vulnerability on one package.
type Advisory struct {
	ID       string
	Severity string // normalised: critical high medium low info
	CVSS     float64
	EPSS     float64
	KEV      bool
	Exploits int
	Verdict  scan.VerdictResult
	Signals  []Signal
	// Reach is the raw reachability outcome; ReachAt is a file:line when known.
	Reach   string
	ReachAt string
	// Fix is the version this advisory alone recommends, if any.
	Fix string
	// FixSource says where Fix came from: "recommended" or "advisory" (the upper
	// bound of its affected range).
	FixSource string
	// AnyUpgrade is set when moving to any other version clears this advisory.
	AnyUpgrade bool
	// FixAvailability is the server's word: available, partial, no_fix.
	FixAvailability string
	// AlsoKnownAs lists the other identifiers of the same vulnerability that were
	// folded into this one (see foldAliases).
	AlsoKnownAs []string
	Ev          scan.EnrichedVuln
}

// FixState is the package-level answer to "how do I fix it".
type FixState int

const (
	// FixUnknown means the data carried no remediation either way.
	FixUnknown FixState = iota
	// FixAvailable means one version clears every advisory.
	FixAvailable
	// FixPartial means a version clears some advisories and not all.
	FixPartial
	// FixNone means no version clears any advisory.
	FixNone
)

// Fix is the lowest version that clears the package's advisories.
type Fix struct {
	State FixState
	// Target is the version to move to. Empty with FixAvailable means a fix is
	// reported to exist but its version was not given.
	Target string
	// Clears and Of describe a partial fix: "2 of 3".
	Clears, Of int
}

// Package is one dependency and everything known about its problems.
type Package struct {
	Name, Version, Ecosystem, Scope string
	// Source is the manifest (or image, or pipeline file) that declared it.
	Source string
	// MoreSources counts further manifests that declare the same package.
	MoreSources int
	Direct      bool
	// Via is the chain from a direct dependency to this one, excluding it.
	Via       []string
	Severity  string
	Malicious bool
	// Advisories are those that count: affected or unverified, worst first.
	Advisories []Advisory
	// RuledOut are advisories matched by name and excluded by version.
	RuledOut []Advisory
	Fix      Fix
	Signals  []Signal
	Group    Group

	// Defence is set only for packages with no fix, and only when asked.
	Defence *defences.Summary
	// DefenceID is the identifier the defence lookup used.
	DefenceID string
	// Controls are the unexpired recorded controls covering this package.
	Controls []defences.Control
	// Lapsed is a recorded control that has expired, if one was found.
	Lapsed *defences.Control
	// Covered reports that every counted advisory has an active control.
	Covered bool

	threat float64
}

// Top is the advisory to name when only one fits.
func (p Package) Top() Advisory {
	if len(p.Advisories) > 0 {
		return p.Advisories[0]
	}
	if len(p.RuledOut) > 0 {
		return p.RuledOut[0]
	}
	return Advisory{}
}

// Label is "name version".
func (p Package) Label() string {
	if p.Version == "" {
		return p.Name
	}
	return p.Name + " " + p.Version
}

// Meta is run context for the header.
type Meta struct {
	ScannedPackages int
	Manifests       int
	// Kinds are the scanners that ran: "sca", "sast", ...
	Kinds   []string
	Elapsed time.Duration
	// VEXSuppressed is how many findings third-party VEX closed.
	VEXSuppressed int
	// Strict records that not-affected findings were counted anyway.
	Strict bool
}

// Report is the whole result.
type Report struct {
	Packages []Package
	Meta     Meta
}

// Counts is the header's partition. Every package with a counting advisory is in
// exactly one of Action, Wait, Protected, Monitored, so the numbers add up.
type Counts struct {
	Advisories int
	Packages   int
	ByGroup    map[Group]int
}

// Counts tallies the report.
func (r Report) Counts() Counts {
	c := Counts{ByGroup: map[Group]int{}}
	for _, p := range r.Packages {
		c.ByGroup[p.Group]++
		if p.Group == GroupNotAffected {
			continue
		}
		c.Packages++
		c.Advisories += len(p.Advisories)
	}
	return c
}

// InGroup returns the packages of one group in print order.
func (r Report) InGroup(g Group) []Package {
	var out []Package
	for _, p := range r.Packages {
		if p.Group == g {
			out = append(out, p)
		}
	}
	return out
}

// NoFix returns the packages whose advisories have no fix.
func (r Report) NoFix() []Package {
	var out []Package
	for _, p := range r.Packages {
		if p.Group != GroupNotAffected && p.Group != GroupUnverified && p.Fix.State == FixNone {
			out = append(out, p)
		}
	}
	return out
}
