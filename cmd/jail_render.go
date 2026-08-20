package cmd

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// ─────────────────────────────────────────────────────────────────────────
// jail_render.go — presenting the verdict.
//
// One renderer for every mode. The difference between `jail`, `jail explain`
// and `jail list` is which sections are worth showing, not a separate format —
// an operator comparing a red pipeline against a local explain run needs the
// same numbers laid out the same way.
// ─────────────────────────────────────────────────────────────────────────

func renderJailResult(cmd *cobra.Command, result *JailRunResult, opts JailRunOptions) {
	if result == nil {
		return
	}
	ctx := display.FromCommand(cmd)

	if result.Exemption != nil {
		if ctx.IsJSON() {
			_ = ctx.Logger.ResultJSON(result.Exemption)
			return
		}
		ctx.Logger.Result(renderJailExemption(result.Exemption))
		return
	}

	if result.Response == nil {
		return
	}
	if ctx.IsJSON() {
		_ = ctx.Logger.ResultJSON(result.Response)
		return
	}
	ctx.Logger.Result(renderJailVerdict(result, opts))
}

func renderJailExemption(resp *vdb.CliJailExemptResponse) string {
	var b strings.Builder
	switch resp.Action {
	case "deactivated":
		b.WriteString("Exemption retired.\n")
	default:
		b.WriteString("Exemption created.\n")
	}
	if e := resp.Exemption; e != nil {
		if e.Uuid != "" {
			fmt.Fprintf(&b, "  uuid    %s\n", e.Uuid)
		}
		if e.RuleUuid != "" {
			fmt.Fprintf(&b, "  rule    %s\n", e.RuleUuid)
		} else if resp.Action != "deactivated" {
			b.WriteString("  rule    (every rule in the policy)\n")
		}
		if e.Reason != "" {
			fmt.Fprintf(&b, "  reason  %s\n", e.Reason)
		}
		if e.ExpiresAt > 0 {
			fmt.Fprintf(&b, "  expires %s (%s)\n",
				time.UnixMilli(e.ExpiresAt).UTC().Format("2006-01-02"),
				pluralise("day", e.DaysLeft))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func renderJailVerdict(result *JailRunResult, opts JailRunOptions) string {
	resp := result.Response
	var b strings.Builder

	b.WriteString(jailVerdictHeadline(resp))
	b.WriteString("\n")

	fmt.Fprintf(&b, "  repository  %s (%s)\n", jailOrDash(resp.Scope.Repo), jailOrDash(resp.Scope.RepoSource))
	fmt.Fprintf(&b, "  branch      %s (%s)\n", jailOrDash(resp.Scope.Branch), jailOrDash(resp.Scope.BranchSource))
	if resp.Policy != nil {
		fmt.Fprintf(&b, "  policy      %s (%s scope, %s)\n",
			resp.Policy.Name, resp.Policy.Source, resp.Policy.EnforcementMode)
	}

	if resp.Verdict == vdb.JailVerdictNoPolicy {
		b.WriteString("\nNo jail policy applies to this repository yet.\n")
		b.WriteString(renderJailWarnings(resp))
		return strings.TrimRight(b.String(), "\n")
	}

	b.WriteString("\n")
	b.WriteString(renderJailRules(resp, opts.Mode == jailModeExplain))

	if fresh := renderJailFreshness(resp); fresh != "" {
		b.WriteString("\n")
		b.WriteString(fresh)
	}

	if ex := renderJailAppliedExemptions(resp); ex != "" {
		b.WriteString("\n")
		b.WriteString(ex)
	}

	if len(result.Artefacts) > 0 {
		b.WriteString("\nArtefacts\n")
		for _, p := range result.Artefacts {
			fmt.Fprintf(&b, "  %s\n", p)
		}
	}

	b.WriteString(renderJailWarnings(resp))

	if opts.NoFail && resp.ExitCode != ExitOK {
		b.WriteString("\n--no-fail is set; exiting 0 despite the verdict above.\n")
	}

	return strings.TrimRight(b.String(), "\n")
}

func jailVerdictHeadline(resp *vdb.CliJailResponse) string {
	s := resp.Summary
	switch resp.Verdict {
	case vdb.JailVerdictJailed:
		return fmt.Sprintf("JAILED — %s breached", pluralise("rule", s.Breaches))
	case vdb.JailVerdictIndeterminate:
		// The wording matters. This is not a pass and not a failure of the code;
		// it is a failure to be able to tell, and whoever reads it needs to look
		// at the pipeline rather than at the dependencies.
		return fmt.Sprintf("INDETERMINATE — %s could not be evaluated against current scan coverage",
			pluralise("rule", s.Indeterminate))
	case vdb.JailVerdictNoPolicy:
		return "NO POLICY"
	default:
		return fmt.Sprintf("CLEAR — %s evaluated", pluralise("rule", s.RulesEvaluated))
	}
}

func renderJailRules(resp *vdb.CliJailResponse, explain bool) string {
	if len(resp.Rules) == 0 {
		return "No rules are configured.\n"
	}

	rules := make([]vdb.CliJailRuleVerdict, len(resp.Rules))
	copy(rules, resp.Rules)
	sort.SliceStable(rules, func(i, j int) bool {
		// Breaches first regardless of configured order — the reason the build
		// is red belongs at the top of the output, not wherever the operator
		// happened to place the rule.
		return jailStateWeight(rules[i].State) < jailStateWeight(rules[j].State)
	})

	var b strings.Builder
	b.WriteString("Rules\n")
	for _, r := range rules {
		fmt.Fprintf(&b, "  %-14s %-12s %s\n", jailStateLabel(r.State), r.Kind, r.Label)
		fmt.Fprintf(&b, "                 %s %s %s (observed %s)\n",
			r.Aggregate, strings.ToLower(r.Operator), jailFloat(r.ThresholdLow), jailFloat(r.Observed))
		if r.Reason != "" {
			fmt.Fprintf(&b, "                 %s\n", r.Reason)
		}
		if r.Stale {
			b.WriteString("                 evaluated on stale or missing coverage\n")
		}
		if r.Ratcheted && r.Baseline != nil {
			fmt.Fprintf(&b, "                 ratchet: was %s on this branch\n", jailFloat(*r.Baseline))
		}
		if r.Deadline > 0 {
			fmt.Fprintf(&b, "                 deadline %s (%s)\n",
				time.UnixMilli(r.Deadline).UTC().Format("2006-01-02"),
				jailDeadlineNote(r.DaysRemaining))
		}
		if explain && len(r.Items) > 0 {
			for _, item := range r.Items {
				fmt.Fprintf(&b, "                   · %s\n", item)
			}
		}
	}
	return b.String()
}

func jailDeadlineNote(daysRemaining int) string {
	if daysRemaining > 0 {
		return pluralise("day", daysRemaining) + " remaining"
	}
	if daysRemaining == 0 {
		return "due today"
	}
	return pluralise("day", -daysRemaining) + " overdue"
}

// jailStateWeight orders rule states so the actionable ones surface first.
func jailStateWeight(state string) int {
	switch state {
	case vdb.JailStateBreach:
		return 0
	case vdb.JailStateIndeterminate:
		return 1
	case vdb.JailStateWarn:
		return 2
	case vdb.JailStateExempt:
		return 3
	case vdb.JailStateSkipped:
		return 4
	default:
		return 5
	}
}

func jailStateLabel(state string) string {
	switch state {
	case vdb.JailStateBreach:
		return "BREACH"
	case vdb.JailStateWarn:
		return "warn"
	case vdb.JailStateIndeterminate:
		return "unknown"
	case vdb.JailStateExempt:
		return "exempt"
	case vdb.JailStateSkipped:
		return "skipped"
	default:
		return "pass"
	}
}

func renderJailFreshness(resp *vdb.CliJailResponse) string {
	f := resp.Freshness
	if len(f.Categories) == 0 && len(f.Missing) == 0 && !f.CommitDrift {
		return ""
	}

	var b strings.Builder
	b.WriteString("Scan coverage\n")
	for _, c := range f.Categories {
		marker := " "
		if c.Stale {
			marker = "!"
		}
		fmt.Fprintf(&b, "  %s %-10s %s old, %s\n",
			marker, c.Category, pluralise("day", c.AgeDays), pluralise("tool", len(c.Tools)))
	}
	if len(f.Missing) > 0 {
		fmt.Fprintf(&b, "  ! no coverage for %s\n", strings.Join(f.Missing, ", "))
	}
	if f.CommitDrift {
		// Reported, never gated. A pull-request build scans the merge commit
		// while the gate runs on the head commit, so treating this as a failure
		// would jail every PR.
		fmt.Fprintf(&b, "    latest scan is at %s; working tree is at %s\n",
			jailShortSHA(f.DriftFrom), jailShortSHA(f.DriftTo))
	}
	return b.String()
}

func renderJailAppliedExemptions(resp *vdb.CliJailResponse) string {
	if len(resp.Exemptions) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Exemptions applied\n")
	for _, e := range resp.Exemptions {
		scope := "every rule"
		if e.RuleUuid != "" {
			scope = "rule " + e.RuleUuid
		}
		fmt.Fprintf(&b, "  %s — %s", scope, e.Reason)
		if e.ExpiresAt > 0 {
			fmt.Fprintf(&b, " (expires in %s)", pluralise("day", e.DaysLeft))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func renderJailWarnings(resp *vdb.CliJailResponse) string {
	if len(resp.Warnings) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\nNotes\n")
	for _, w := range resp.Warnings {
		fmt.Fprintf(&b, "  %s\n", w)
	}
	return b.String()
}

func jailFloat(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%.2f", f)
}

func jailOrDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func jailShortSHA(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	if s == "" {
		return "—"
	}
	return s
}
