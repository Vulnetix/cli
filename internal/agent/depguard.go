package agent

import (
	"fmt"
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/internal/fix"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/internal/scaview"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// Assessment is everything known about one package the agent is about to add.
type Assessment struct {
	Candidate

	// Resolved is the version that would actually be installed when the command
	// did not pin one. Empty when nothing could resolve it, which is not the
	// same as the package being fine.
	Resolved string

	// NameLevel records that the command named no version and nothing could
	// resolve the one it would install, so Insight describes the package's
	// whole history rather than a release. A malware flag at that level means
	// "some version has been malicious", which is true of express and is not a
	// reason to refuse `npm i express`.
	NameLevel bool

	Vulns   []scan.EnrichedVuln
	Insight *vdb.CliPackageInsight

	// Unknown records that the lookup could not answer for this package: no
	// credential, no network, an unparseable manifest, a timeout. It is never a
	// verdict, and it never blocks. Absence of an answer is not an answer.
	Unknown bool
	// ExploitsGated records that the server withheld exploit intelligence
	// rather than reporting none.
	ExploitsGated bool
}

// version returns the version to reason about: what the command asked for, or
// what would resolve if it asked for nothing.
func (a Assessment) version() string {
	if a.Candidate.Version != "" {
		return a.Candidate.Version
	}
	return a.Resolved
}

// EvaluateDependency decides what, if anything, to say about a set of packages
// an agent is about to add.
//
// The rule the whole guard turns on: when every package satisfies the
// repository's own Safe Harbour policy, this returns Silent and the agent is
// not interrupted. A guard that comments on every install is one people switch
// off, and then it is not a guard.
func EvaluateDependency(p Policy, assessments []Assessment) Response {
	resp := Response{Event: EventPreToolUse, Decision: Silent}
	if !p.Active() {
		return resp
	}

	var blocked, warned []string

	for _, a := range assessments {
		// A package nothing is known about is left alone. Reporting "we could
		// not check this" on every install during an outage is noise, and
		// blocking on it would make a network blip stop the work.
		if a.Unknown {
			continue
		}

		signals := signalsFor(p, a)
		if len(signals) == 0 {
			continue
		}

		worst := Silent
		for _, s := range signals {
			if d := p.DependencyGuard.Decide(s); d > worst {
				worst = d
			}
		}
		if worst == Silent {
			continue
		}

		card := renderAssessment(a, p)
		if worst == Block {
			blocked = append(blocked, card)
		} else {
			warned = append(warned, card)
		}
	}

	switch {
	case len(blocked) > 0:
		resp.Decision = Block
		// A block names everything worth knowing, not just the reason it
		// blocked: the agent is about to choose what to do instead, and the
		// warnings are part of that choice.
		resp.Message = joinSections(append(blocked, warned...))
	case len(warned) > 0:
		resp.Decision = Inform
		resp.Message = joinSections(warned)
	}
	return resp
}

// signalsFor lists everything true about a package that the policy might act
// on.
func signalsFor(p Policy, a Assessment) []Signal {
	var out []Signal

	if a.Insight != nil && a.Insight.IsMalicious {
		if a.NameLevel {
			// A fact about the package's history, not about what installs.
			out = append(out, SignalMalwareUnresolved)
		} else {
			out = append(out, SignalMalware)
		}
	}
	if a.Insight != nil && a.Insight.IsEOL {
		out = append(out, SignalEOL)
	}

	kevCritical := false
	high := false
	for _, v := range a.Vulns {
		sev := scaview.NormaliseSeverity(v.MaxSeverity)
		// "Being exploited" is the CLI's own definition, the one `--exploits
		// active` gates a pipeline on: any KEV catalogue, or a maturity the
		// server reported as active. Writing a second definition here would let
		// the guard and the build gate disagree about the same advisory, and
		// the KEV booleans alone are not enough — cli.sca reports Log4Shell's
		// exploitation through maturity rather than a catalogue flag.
		if sev == "critical" && scan.ExploitMeetsThreshold(v, "active") {
			kevCritical = true
		}
		if sev == "critical" || sev == "high" {
			high = true
		}
	}
	if kevCritical {
		out = append(out, SignalKEVCritical)
	}
	if high {
		out = append(out, SignalSeverityHigh)
	}

	if isUnpinned(a.Candidate.Version) {
		out = append(out, SignalUnpinned)
	}
	if p.CooldownDays > 0 && publishedWithin(a.Insight, p.CooldownDays) {
		out = append(out, SignalCooldown)
	}

	// Safe Harbour last, and only for a package that has something wrong with
	// it as requested.
	//
	// This is what keeps the guard quiet. A newer safe version existing is not,
	// on its own, a reason to interrupt: almost every package has one, and
	// "there is a later release" is a fact about the registry rather than about
	// the decision being made. It matters as the answer to a problem, so it
	// fires only when there is a problem to answer.
	if len(a.Vulns) > 0 {
		if target, decision := targetFor(a, p); !decision.Skipped && target != "" {
			out = append(out, SignalBelowTarget)
		}
	}

	return out
}

// targetFor resolves the Safe Harbour target under the repository's strategy.
func targetFor(a Assessment, p Policy) (string, fix.TargetDecision) {
	if a.Insight == nil {
		return "", fix.TargetDecision{Skipped: true, Reason: "no package insight"}
	}
	return fix.ResolveTarget(
		a.version(),
		p.SafeHarbourStrategy,
		a.Insight.LatestVersions,
		a.Insight.SafeVersions,
		a.Insight.SafeHarbour,
		p.MaxMajorBump,
	)
}

// renderAssessment produces the text the model reads.
//
// It goes through scaview, so this is the same card the editor shows on hover
// and the same wording the terminal prints. A developer who sees one and an
// agent that sees the other are looking at one answer.
func renderAssessment(a Assessment, p Policy) string {
	s := scaview.Subject{
		Pkg: scaview.Pkg{
			Name:      a.Candidate.Name,
			Version:   a.version(),
			Ecosystem: a.Candidate.Ecosystem,
		},
		Vulns:         a.Vulns,
		OwnVulns:      len(a.Vulns),
		ExploitsGated: a.ExploitsGated,
		Fix:           fixFor(a, p),
	}
	if a.Insight != nil && (a.Insight.IsMalicious || a.Insight.IsEOL) {
		s.Insight = &scaview.Insight{
			Malicious: a.Insight.IsMalicious,
			EOL:       a.Insight.IsEOL,
			EOLFrom:   strings.TrimSpace(a.Insight.EOLFrom),
		}
	}

	card := scaview.Card(s)

	if isUnpinned(a.Candidate.Version) && a.Resolved != "" {
		card += fmt.Sprintf("\n**Unpinned.** `%s` resolves to %s today; a later install may differ.\n",
			displaySpec(a.Candidate), a.Resolved)
	}
	if a.NameLevel && a.Insight != nil && a.Insight.IsMalicious {
		card += fmt.Sprintf("\n**About the name, not a release.** At least one published version of `%s` "+
			"is on a malicious-package list, and the version this command would install could not be "+
			"determined. Pin one explicitly and it will be judged on its own.\n", a.Candidate.Name)
	}
	return strings.TrimRight(card, "\n")
}

func fixFor(a Assessment, p Policy) scaview.Fix {
	if len(a.Vulns) == 0 && (a.Insight == nil || !a.Insight.IsMalicious) {
		return scaview.Fix{State: scaview.FixNotApplicable}
	}
	target, decision := targetFor(a, p)
	if decision.Skipped || target == "" {
		return scaview.Fix{State: scaview.FixNone, Reason: decision.Reason}
	}
	f := scaview.Fix{State: scaview.FixAvailable, Target: target}
	if a.Insight != nil && a.Insight.SafeHarbour != nil && a.Insight.SafeHarbour.Recommendation != nil {
		f.Reason = strings.TrimSpace(a.Insight.SafeHarbour.Recommendation.Reason)
	}
	return f
}

// displaySpec renders the package the way the command asked for it.
func displaySpec(c Candidate) string {
	if c.Version == "" {
		return c.Name
	}
	return c.Name + "@" + c.Version
}

// isUnpinned reports whether a requested version leaves the resolver a choice.
//
// An empty version is unpinned by definition: the command named a package and
// let the manager pick.
func isUnpinned(version string) bool {
	v := strings.TrimSpace(version)
	if v == "" {
		return true
	}
	if strings.ContainsAny(v, "^~*><|") {
		return true
	}
	switch strings.ToLower(v) {
	case "latest", "next", "beta", "alpha", "canary", "*", "x":
		return true
	}
	return false
}

// publishedWithin reports whether the version landed inside the cooldown.
func publishedWithin(in *vdb.CliPackageInsight, days int) bool {
	if in == nil || in.PublishedAt == nil || days <= 0 {
		return false
	}
	published := time.UnixMilli(*in.PublishedAt)
	return time.Since(published) < time.Duration(days)*24*time.Hour
}

// joinSections separates one package's card from the next, and labels the whole
// as a report rather than an instruction.
//
// The framing matters. Claude Code marks hook-injected text as content it did
// not produce, so text that reads as a command to the model is both ignored and
// suspicious. A report about a package is neither.
func joinSections(sections []string) string {
	var b strings.Builder
	b.WriteString("Vulnetix checked the dependencies this command would add.\n\n")
	b.WriteString(strings.Join(sections, "\n\n---\n\n"))
	return b.String()
}
