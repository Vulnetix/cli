package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/defences"
	"github.com/vulnetix/cli/v3/internal/display"
)

// DefendView is everything `vulnetix defend` shows for one finding.
type DefendView struct {
	PackageLabel string
	ID           string
	Fix          Fix
	// Exploit is a one-line description of the public exploit, when known.
	Exploit string
	Summary defences.Summary
	// Fits are the enforcement points inferred from the repository.
	Fits map[defences.Kind]defences.Hint
}

const pricingURL = "https://www.vulnetix.com/pricing"

// RenderDefend draws the read view: what exists, in which lane, how sure the
// rule is, how it should be started, and what it does not cover. Block and
// detect are separate sections, because one stops the request and the other
// only tells you it happened.
func RenderDefend(v DefendView, o Options, t *display.Terminal) string {
	s := NewStyle(t, o)
	var b strings.Builder
	fix := "no fix"
	switch v.Fix.State {
	case FixAvailable:
		fix = "a fix exists"
		if v.Fix.Target != "" {
			fix = "fixed in " + v.Fix.Target
		}
	case FixPartial:
		fix = "partly fixed"
	case FixUnknown:
		fix = "fix status unknown"
	}
	// Asked by id alone there is no package, and the label is the id: say it once.
	if v.PackageLabel == "" || strings.EqualFold(v.PackageLabel, v.ID) {
		fmt.Fprintf(&b, "\n %s %s %s\n", s.Bold(v.ID), s.Dim(s.G.Sep), s.Hot(fix))
	} else {
		fmt.Fprintf(&b, "\n %s %s %s %s %s\n", s.Bold(v.PackageLabel), s.Dim(s.G.Sep), v.ID, s.Dim(s.G.Sep), s.Hot(fix))
	}
	if v.Exploit != "" {
		fmt.Fprintf(&b, " %s  %s\n", s.Dim("exploit"), v.Exploit)
	}

	d := v.Summary
	switch d.State {
	case defences.StateUnavailable:
		fmt.Fprintf(&b, "\n %s %s\n", s.Defence(s.G.Defence), "Defence lookup is not available in this version yet.")
		fmt.Fprintf(&b, "   %s\n", s.Dim("Block rules and detections for "+v.ID+" will be listed here once it ships."))
		return b.String()
	case defences.StateNotIndexed:
		fmt.Fprintf(&b, "\n %s %s\n", s.Defence(s.G.Defence), "Not indexed: that is not an advisory identifier the database can look up.")
		fmt.Fprintf(&b, "   %s\n", s.Dim(v.ID+" has no alias in one of those families, so nothing can be looked up."))
		return b.String()
	case defences.StateNotChecked:
		fmt.Fprintf(&b, "\n %s %s\n", s.Defence(s.G.Defence), "Not checked"+reasonSuffix(d.Reason))
		return b.String()
	case defences.StateFailed:
		fmt.Fprintf(&b, "\n %s %s\n", s.Warn(s.G.Unknown), "The lookup failed"+reasonSuffix(d.Reason)+". Run it again.")
		return b.String()
	case defences.StateNone:
		fmt.Fprintf(&b, "\n %s %s\n", s.Defence(s.G.Defence), "Nothing is published for "+v.ID+" yet.")
		fmt.Fprintf(&b, "   %s\n", s.Dim("That means no rule has been built, not that none can be."))
		fmt.Fprintf(&b, "\n %s\n   %s\n", s.Bold("NEXT"), s.Cmd("vulnetix vdb workarounds "+v.ID))
		return b.String()
	case defences.StateGated:
		writeLaneCounts(&b, s, "BLOCK", d.Block, "they stop the request")
		writeLaneCounts(&b, s, "DETECT", d.Detect, "they tell you it happened")
		fmt.Fprintf(&b, "\n %s Rule bodies and downloads need a Pro plan: %s\n", s.Defence(s.G.Defence), s.Cmd(pricingURL))
		return b.String()
	}

	writeLaneRules(&b, s, "BLOCK", d.Block, "virtual patch", "virtual patches", "they stop the request", v.Fits, true)
	writeLaneRules(&b, s, "DETECT", d.Detect, "countermeasure", "countermeasures", "it tells you it happened", v.Fits, false)
	if d.Detect.Count > 0 {
		fmt.Fprintf(&b, " %s\n", s.Dim("Detection is not prevention. It does not stop the exploit."))
	}

	b.WriteString("\n " + s.Bold("NEXT") + "\n")
	if k, ok := firstFit(d, v.Fits); ok {
		fmt.Fprintf(&b, "   %s\n", s.Cmd(fmt.Sprintf("vulnetix defend %s --for %s -o defences/", v.ID, defences.Flag(k))))
		if len(v.Fits) > 1 {
			fmt.Fprintf(&b, "   %s   %s\n", s.Cmd(fmt.Sprintf("vulnetix defend %s --for fits -o defences/", v.ID)), s.Dim("every format your repo suggests"))
		}
	} else if rules := d.Rules(); len(rules) > 0 {
		fmt.Fprintf(&b, "   %s\n", s.Cmd(fmt.Sprintf("vulnetix defend %s --for %s -o defences/", v.ID, defences.Flag(rules[0].Kind))))
	}
	return b.String()
}

func reasonSuffix(r string) string {
	if r == "" {
		return ""
	}
	return " (" + r + ")"
}

func writeLaneCounts(b *strings.Builder, s *Style, title string, l defences.LaneSummary, what string) {
	if l.Count == 0 {
		return
	}
	var names []string
	for _, k := range l.Kinds() {
		names = append(names, fmt.Sprintf("%s ×%d", defences.Name(k), l.ByKind[k]))
	}
	fmt.Fprintf(b, "\n %s %s\n", s.Defence(s.Bold(title)), s.Dim(fmt.Sprintf("%s %d %s", s.G.Sep, l.Count, what)))
	fmt.Fprintf(b, "   %s\n", strings.Join(names, ", "))
}

func writeLaneRules(b *strings.Builder, s *Style, title string, l defences.LaneSummary, one, many, what string, fits map[defences.Kind]defences.Hint, blocking bool) {
	if l.Count == 0 {
		return
	}
	noun := many
	if l.Count == 1 {
		noun = one
	}
	fmt.Fprintf(b, "\n %s %s\n", s.Defence(s.Bold(title)), s.Dim(fmt.Sprintf("%s %d %s %s %s", s.G.Sep, l.Count, noun, s.G.Sep, what)))
	fmt.Fprintf(b, " %s\n", s.Rule(s.Width-2))

	rules := append([]defences.Rule{}, l.Rules...)
	sort.SliceStable(rules, func(i, j int) bool {
		_, fi := fits[rules[i].Kind]
		_, fj := fits[rules[j].Kind]
		if fi != fj {
			return fi
		}
		return confRank(rules[i].Confidence) < confRank(rules[j].Confidence)
	})
	for _, r := range rules {
		head := pad(s.Bold(defences.Name(r.Kind)), 16)
		if r.Confidence != "" {
			head += s.Dim("confidence ") + r.Confidence + "   "
		}
		if blocking {
			if m := modeWords(r.DeployMode); m != "" {
				head += s.Dim("start in ") + m + "   "
			} else if r.DeployMode != "" {
				head += s.Dim("start in ") + r.DeployMode + "   "
			}
		}
		if r.FalsePositiveRisk != "" {
			head += s.Dim("false positives ") + strings.ToLower(r.FalsePositiveRisk)
		}
		fmt.Fprintf(b, " %s\n", strings.TrimRight(head, " "))
		ind := strings.Repeat(" ", 17)
		if h, ok := fits[r.Kind]; ok {
			fmt.Fprintf(b, "%s%s %s\n", ind, s.Good("▸ fits your repo"), s.Dim(h.Where()+" "+s.G.Sep+" inferred, not verified as deployed"))
		}
		if r.CoverageNotes != "" {
			for i, line := range wrapText(r.CoverageNotes, s.Width-len(ind)-10) {
				label := "         "
				if i == 0 {
					label = s.Dim("coverage")
				}
				fmt.Fprintf(b, "%s%s%s\n", ind, label, line)
			}
		}
		if r.ExploitSource != "" {
			fmt.Fprintf(b, "%s%s%s\n", ind, s.Dim("from    "), r.ExploitSource)
		}
		if r.ConsoleURL != "" {
			fmt.Fprintf(b, "%s%s%s\n", ind, s.Dim("console "), r.ConsoleURL)
		}
	}
}

func confRank(c string) int {
	switch strings.ToUpper(c) {
	case "HIGH":
		return 0
	case "MEDIUM":
		return 1
	case "LOW":
		return 2
	}
	return 3
}

// firstFit is the first block rule whose format the repo suggests, falling back
// to none: a suggestion that does not fit the repo is not made.
func firstFit(d defences.Summary, fits map[defences.Kind]defences.Hint) (defences.Kind, bool) {
	for _, r := range d.Block.Rules {
		if _, ok := fits[r.Kind]; ok {
			return r.Kind, true
		}
	}
	for _, r := range d.Detect.Rules {
		if _, ok := fits[r.Kind]; ok {
			return r.Kind, true
		}
	}
	return "", false
}

// wrapText breaks text on spaces to at most width cells per line.
func wrapText(text string, width int) []string {
	if width < 20 {
		width = 20
	}
	var lines []string
	cur := ""
	for _, w := range strings.Fields(text) {
		if cur != "" && display.Width(cur)+1+display.Width(w) > width {
			lines = append(lines, cur)
			cur = w
			continue
		}
		if cur == "" {
			cur = w
		} else {
			cur += " " + w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}
