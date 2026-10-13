package report

import (
	"fmt"
	"strings"

	"github.com/vulnetix/cli/v3/internal/defences"
)

// RenderGitHub emits workflow commands that GitHub Actions turns into
// annotations on the manifest line, one per package. Findings that need action
// are errors, the rest warnings, and anything with a recorded control a notice.
func RenderGitHub(r Report) string {
	var b strings.Builder
	for _, g := range groupOrder {
		level := ""
		switch g {
		case GroupAction:
			level = "error"
		case GroupWait, GroupUnverified:
			level = "warning"
		case GroupProtected, GroupMonitored:
			level = "notice"
		default:
			continue
		}
		for _, p := range r.InGroup(g) {
			props := ""
			if p.Source != "" {
				props = "file=" + ghProp(p.Source) + ","
			}
			title := fmt.Sprintf("%s (%s)", p.Label(), SevWord(p.Severity))
			fmt.Fprintf(&b, "::%s %stitle=%s::%s\n", level, props, ghProp(title), ghData(annotationMessage(p)))
		}
	}
	return b.String()
}

func annotationMessage(p Package) string {
	top := p.Top()
	msg := top.ID
	if n := len(p.Advisories) - 1; n > 0 {
		msg += fmt.Sprintf(" and %d more", n)
	}
	msg += "."
	var sig []string
	for _, s := range top.Signals {
		sig = append(sig, s.Label)
	}
	if len(sig) > 0 {
		msg += " " + strings.Join(sig, ", ") + "."
	}
	switch p.Fix.State {
	case FixAvailable:
		if p.Fix.Target != "" {
			msg += " Upgrade to " + p.Fix.Target + "."
		}
	case FixPartial:
		msg += fmt.Sprintf(" Upgrade to %s clears %d of %d.", p.Fix.Target, p.Fix.Clears, p.Fix.Of)
	case FixNone:
		msg += " No fix."
		if d := p.Defence; d != nil && (d.State == defences.StateAvailable || d.State == defences.StateGated) {
			var parts []string
			if d.Block.Count > 0 {
				parts = append(parts, fmt.Sprintf("%d block %s", d.Block.Count, pluralWord(d.Block.Count, "rule", "rules")))
			}
			if d.Detect.Count > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", d.Detect.Count, pluralWord(d.Detect.Count, "detection", "detections")))
			}
			msg += " " + strings.Join(parts, " and ") + " available."
		}
	}
	return msg
}

// StepSummary renders the report as Markdown for $GITHUB_STEP_SUMMARY.
func StepSummary(r Report) string {
	c := r.Counts()
	var b strings.Builder
	b.WriteString("## Vulnetix scan\n\n")
	if c.Packages == 0 {
		b.WriteString("No vulnerabilities found.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "**%s** &middot; %d need action &middot; %d can wait", advisoriesIn(c),
		c.ByGroup[GroupAction], c.ByGroup[GroupWait])
	if n := c.ByGroup[GroupUnverified]; n > 0 {
		fmt.Fprintf(&b, " &middot; %d unverified", n)
	}
	if n := c.ByGroup[GroupProtected] + c.ByGroup[GroupMonitored]; n > 0 {
		fmt.Fprintf(&b, " &middot; %d with a recorded control", n)
	}
	if n := c.ByGroup[GroupNotAffected]; n > 0 {
		fmt.Fprintf(&b, " &middot; %d not affected", n)
	}
	b.WriteString("\n\n| Group | Severity | Package | Fix | Advisory | Signals |\n|---|---|---|---|---|---|\n")
	for _, g := range groupOrder {
		for _, p := range r.InGroup(g) {
			if g == GroupNotAffected {
				continue
			}
			fix := ""
			switch p.Fix.State {
			case FixAvailable:
				fix = "&rarr; " + p.Fix.Target
			case FixPartial:
				fix = fmt.Sprintf("&rarr; %s (%d of %d)", p.Fix.Target, p.Fix.Clears, p.Fix.Of)
			case FixNone:
				fix = "no fix"
			}
			ids := p.Top().ID
			if n := len(p.Advisories) - 1; n > 0 {
				ids += fmt.Sprintf(" +%d", n)
			}
			var sig []string
			for _, s := range p.Top().Signals {
				sig = append(sig, s.Label)
			}
			fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s | %s |\n", g.Title(), SevWord(p.Severity), p.Label(), fix, ids, strings.Join(sig, ", "))
		}
	}
	return b.String()
}

// Workflow-command escaping, per the GitHub Actions toolkit.
func ghData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

func ghProp(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}
