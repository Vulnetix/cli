package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/scaview"
)

// The four rule-engine scanners share the SAST grammar (a verdict line, groups
// that say what to do, a NEXT block) but not its unit. SAST groups by rule,
// secrets by credential, and iac and containers by the resource or image you
// edit. codeFlavour picks which.
type flavour int

const (
	flavourSAST flavour = iota
	flavourSecrets
	flavourIaC
	flavourContainers
)

func codeFlavour(r CodeReport) flavour {
	switch strings.ToLower(strings.TrimSpace(r.Label)) {
	case "secrets":
		return flavourSecrets
	case "iac":
		return flavourIaC
	case "container", "containers":
		return flavourContainers
	}
	return flavourSAST
}

// credentialKey identifies the secret a line holds without keeping it. The
// match span is not recorded, so the credential is the line's most random-looking
// token: long, mixed, high in entropy. The key is a hash used only to decide
// that two places hold the same value; it is never printed. A line with no such
// token has no identity beyond its place, so it is never merged with another.
func credentialKey(f CodeFinding) string {
	best, bestE := "", 0.0
	split := func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("+/_-.", r))
	}
	for _, tok := range strings.FieldsFunc(f.Snippet, split) {
		tok = strings.Trim(tok, "-_.")
		if len(tok) < 16 {
			continue
		}
		var digit, upper, lower bool
		for _, c := range tok {
			switch {
			case unicode.IsDigit(c):
				digit = true
			case unicode.IsUpper(c):
				upper = true
			case unicode.IsLower(c):
				lower = true
			}
		}
		if !digit && !(upper && lower) {
			continue
		}
		e := entropy(tok)
		if e < 3.2 {
			continue
		}
		if e > bestE || (e == bestE && len(tok) > len(best)) {
			best, bestE = tok, e
		}
	}
	if best == "" {
		return fmt.Sprintf("%s:%d", f.Path, f.Line)
	}
	sum := sha256.Sum256([]byte(best))
	return hex.EncodeToString(sum[:8])
}

func entropy(s string) float64 {
	counts := map[rune]int{}
	n := 0
	for _, c := range s {
		counts[c]++
		n++
	}
	var e float64
	for _, c := range counts {
		p := float64(c) / float64(n)
		e -= p * math.Log2(p)
	}
	return e
}

// credential is the unit of the secrets report: one value and every place it
// is written, because rotating it once fixes all of them.
type credential struct {
	id, title, severity string
	places              []CodeFinding
	committed, blamed   bool
	historyOnly         bool
	commit              string
	at                  time.Time
}

func credentialsOf(fs []CodeFinding) []*credential {
	idx := map[string]*credential{}
	var out []*credential
	for _, f := range fs {
		key := f.RuleID + "|" + credentialKey(f)
		c, ok := idx[key]
		if !ok {
			c = &credential{id: f.RuleID, title: ruleTitle(f), severity: f.Severity}
			idx[key] = c
			out = append(out, c)
		}
		c.places = append(c.places, f)
		if f.Blamed {
			c.blamed = true
		}
		// The oldest commit is when the credential was first exposed.
		if f.Committed && (!c.committed || f.CommittedAt.Before(c.at)) {
			c.committed, c.commit, c.at = true, f.Commit, f.CommittedAt
		}
	}
	for _, c := range out {
		c.places = dedupePlaces(c.places)
		c.historyOnly = true
		for _, p := range c.places {
			c.historyOnly = c.historyOnly && p.InHistory
		}
		sort.SliceStable(c.places, func(i, j int) bool {
			if c.places[i].Path != c.places[j].Path {
				return c.places[i].Path < c.places[j].Path
			}
			return c.places[i].Line < c.places[j].Line
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := scaview.SeverityRank(a.severity), scaview.SeverityRank(b.severity); ra != rb {
			return ra < rb
		}
		if len(a.places) != len(b.places) {
			return len(a.places) > len(b.places)
		}
		if a.id != b.id {
			return a.id < b.id
		}
		return placeLoc(a.places[0]) < placeLoc(b.places[0])
	})
	return out
}

// agoPhrase is "3 days ago", "2 months ago".
func agoPhrase(now, then time.Time) string {
	if now.IsZero() {
		now = time.Now()
	}
	d := now.Sub(then)
	switch {
	case d < 24*time.Hour:
		return "today"
	case d < 90*24*time.Hour:
		n := int(d / (24 * time.Hour))
		return fmt.Sprintf("%d %s ago", n, pluralWord(n, "day", "days"))
	case d < 2*365*24*time.Hour:
		n := int(d / (30 * 24 * time.Hour))
		return fmt.Sprintf("%d months ago", n)
	}
	return fmt.Sprintf("%d years ago", int(d/(365*24*time.Hour)))
}

// exposure is "committed in a1b2c3d, 41 days ago", or "" when git was not asked.
func (c *credential) exposure(o Options) string {
	if !c.committed {
		return ""
	}
	sha := c.commit
	if len(sha) > 7 {
		sha = sha[:7]
	}
	note := "committed in " + sha
	if !c.at.IsZero() {
		note += ", " + agoPhrase(o.Now, c.at)
	}
	if c.historyOnly {
		note = "removed from the tree, still in history: " + note
	}
	return note
}

type secretView struct {
	rotate, fresh, wait, tests []*credential
	vendored                   codeView
	places                     [5]int
	files                      map[string]bool
}

func buildSecretView(r CodeReport, o Options) secretView {
	var v secretView
	v.files = map[string]bool{}
	var groups [4][]CodeFinding
	for _, f := range r.Findings {
		if o.MinSeverity != "" && scaview.SeverityKnown(o.MinSeverity) &&
			scaview.SeverityRank(f.Severity) > scaview.SeverityRank(o.MinSeverity) {
			continue
		}
		g := codeGroupOf(f, o)
		groups[g] = append(groups[g], f)
		v.files[f.Path] = true
	}
	for _, c := range credentialsOf(groups[codeAction]) {
		if c.blamed && !c.committed {
			v.fresh = append(v.fresh, c)
		} else {
			v.rotate = append(v.rotate, c)
		}
	}
	v.wait = credentialsOf(groups[codeWait])
	v.tests = credentialsOf(groups[codeTests])
	// Vendored files keep the by-rule list the SAST report draws.
	vr := r
	vr.Findings = groups[codeVendored]
	v.vendored = buildCodeView(vr, o)
	count := func(cs ...[]*credential) int {
		n := 0
		for _, list := range cs {
			for _, c := range list {
				n += len(c.places)
			}
		}
		return n
	}
	v.places[0], v.places[1], v.places[2] = count(v.rotate, v.fresh), count(v.wait), count(v.tests)
	v.places[3] = len(groups[codeVendored])
	return v
}

func (v secretView) credentials() int {
	return len(v.rotate) + len(v.fresh) + len(v.wait) + len(v.tests) + len(v.vendored.vendored)
}

func (v secretView) allPlaces() int {
	return v.places[0] + v.places[1] + v.places[2] + v.places[3]
}

func secretsHeadline(creds, places int) string {
	return fmt.Sprintf("%s in %s", plural(creds, "credential"), plural(places, "place"))
}

func renderSecrets(r CodeReport, o Options, t *display.Terminal) string {
	s := NewStyle(t, o)
	v := buildSecretView(r, o)
	total := v.allPlaces()

	if o.Quiet {
		if total == 0 {
			return ""
		}
		return fmt.Sprintf("%s Secrets: %s\n", s.Bad(s.G.Fail), secretsHeadline(v.credentials(), total))
	}
	var b strings.Builder
	if total == 0 {
		fmt.Fprintf(&b, " %s %s\n", s.Good(s.G.OK), s.Bold("No secrets found"))
		if r.RulesLoaded > 0 {
			fmt.Fprintf(&b, "   %s\n", s.Dim(rulesPhrase(r)+" evaluated"))
		}
		return b.String()
	}

	mark := s.Bad(s.G.Fail)
	if len(v.rotate)+len(v.fresh) == 0 {
		mark = s.Warn(s.G.Fail)
	}
	head := fmt.Sprintf(" %s %s %s", mark, s.Bold("SECRETS"), s.Bold(secretsHeadline(v.credentials(), total)))
	var parts []string
	if n := len(v.rotate); n > 0 {
		parts = append(parts, s.Bad(fmt.Sprintf("%d to rotate", n)))
	}
	if n := len(v.fresh); n > 0 {
		parts = append(parts, s.Hot(fmt.Sprintf("%d not committed", n)))
	}
	if n := len(v.wait); n > 0 {
		parts = append(parts, s.Warn(fmt.Sprintf("%d can wait", n)))
	}
	if n := len(v.tests); n > 0 {
		parts = append(parts, s.Dim(fmt.Sprintf("%d in tests", n)))
	}
	if n := v.places[3]; n > 0 {
		parts = append(parts, s.Dim(fmt.Sprintf("%d vendored", n)))
	}
	b.WriteString(headLine(head, strings.Join(parts, " "+s.Dim(s.G.Sep)+" "), s))
	var sub []string
	if r.RulesLoaded > 0 {
		sub = append(sub, rulesPhrase(r)+" ran")
	}
	sub = append(sub, "one value in several files counts once", "values are never printed")
	if s.Width >= tierCompact {
		fmt.Fprintf(&b, "   %s\n", s.Dim(strings.Join(sub, " "+s.G.Sep+" ")))
	}

	if len(v.rotate) > 0 {
		b.WriteString("\n" + secretSection(s, "ROTATE NOW", len(v.rotate), "committed to production code"))
		for i, c := range v.rotate {
			if i > 0 && o.Verbosity >= 1 {
				b.WriteString("\n")
			}
			b.WriteString(renderCredential(c, v.rotate, o, s))
		}
	}
	if len(v.fresh) > 0 {
		b.WriteString("\n" + secretSection(s, "NOT COMMITTED", len(v.fresh), "remove it now and it never reaches the history"))
		for _, c := range v.fresh {
			b.WriteString(renderCredential(c, v.fresh, o, s))
		}
	}
	if len(v.wait) > 0 {
		b.WriteString("\n" + secretSection(s, "CAN WAIT", len(v.wait), "medium and low confidence"))
		limit := len(v.wait)
		if o.Verbosity == 0 && limit > 7 {
			limit = 7
		}
		for _, c := range v.wait[:limit] {
			b.WriteString(renderCredential(c, v.wait, o, s))
		}
		if rest := len(v.wait) - limit; rest > 0 {
			b.WriteString(indentFor(s) + s.Dim(fmt.Sprintf("+ %d more %s -v lists every one", rest, s.G.Sep)) + "\n")
		}
	}
	if len(v.tests) > 0 {
		b.WriteString("\n" + codeSectionNote(s, "IN TESTS", fmt.Sprintf("%s %s fixtures, listed not ranked", plural(len(v.tests), "credential"), s.G.Sep)))
		for _, c := range v.tests {
			b.WriteString(renderCredentialLine(c, v.tests, s))
		}
	}
	if len(v.vendored.vendored) > 0 {
		b.WriteString("\n" + codeSectionNote(s, "VENDORED", fmt.Sprintf("%s %s third-party files in the tree",
			plural(v.places[3], "place"), s.G.Sep)))
		b.WriteString(renderVendored(v.vendored.vendored, s))
	}
	b.WriteString(secretsNext(v, o, s))
	return b.String()
}

// headLine puts counts on the right of a headline when they fit, else beneath.
func headLine(head, counts string, s *Style) string {
	if gap := s.Width - 1 - vis(head) - vis(counts); gap >= 2 && s.Width >= tierCompact {
		return head + strings.Repeat(" ", min(gap, 10)) + counts + "\n"
	}
	return head + "\n   " + counts + "\n"
}

func secretSection(s *Style, title string, n int, note string) string {
	head := " " + s.Bold(title) + s.Dim(" "+s.G.Sep+" "+plural(n, "credential"))
	if note != "" && s.Width >= tierCompact {
		head += s.Dim(" " + s.G.Sep + " " + note)
	}
	return head + "\n " + s.Rule(s.Width-2) + "\n"
}

// alsoIn names the other places a credential is written.
func alsoIn(c *credential, o Options, s *Style, room int) []string {
	if len(c.places) < 2 {
		return nil
	}
	var rest []string
	for _, p := range c.places[1:] {
		rest = append(rest, credLoc(p))
	}
	if o.Verbosity >= 1 {
		return rest
	}
	line := "also in "
	for i, p := range rest {
		left := len(rest) - i
		item := p
		if i > 0 {
			item = " " + s.G.Sep + " " + p
		}
		tail := ""
		if left > 1 {
			tail = fmt.Sprintf(" +%d", left-1)
		}
		if display.Width(line)+display.Width(item)+len(tail) > room && i > 0 {
			return []string{line + fmt.Sprintf(" +%d more", left)}
		}
		line += item
	}
	return []string{line}
}

// renderCredential is one credential: its head, how it was exposed, and the
// other places it is written.
func renderCredential(c *credential, group []*credential, o Options, s *Style) string {
	var b strings.Builder
	dot := s.Sev(c.severity, s.G.Dot)
	first := credLoc(c.places[0])
	note := c.exposure(o)
	if s.Width < tierCompact {
		fmt.Fprintf(&b, " %s %s  %s\n", dot, s.Sev(c.severity, SevWord(c.severity)), s.Bold(c.id))
		b.WriteString("   " + s.clip(c.title, s.Width-4) + "\n")
		b.WriteString("   " + s.Path(s.clip(first, s.Width-4)) + "\n")
		if note != "" {
			b.WriteString("   " + s.Warn(s.clip(note, s.Width-4)) + "\n")
		}
		if n := len(c.places) - 1; n > 0 {
			b.WriteString("   " + s.Dim(fmt.Sprintf("also in %d more %s", n, pluralWord(n, "place", "places"))) + "\n")
		}
		return b.String()
	}
	titleW, idW := 0, 0
	for _, g := range group {
		titleW = max(titleW, display.Width(g.title))
		idW = max(idW, len(g.id))
	}
	titleW = min(titleW, 34) + 2
	idW += 2
	left := " " + dot + " " + pad(s.Sev(c.severity, SevWord(c.severity)), 10) + pad(s.clip(c.title, titleW-2), titleW) + pad(s.Dim(c.id), idW)
	b.WriteString(left + s.Path(s.clip(first, max(10, codeRowWidth(s)-1-vis(left)))) + "\n")
	ind := indentFor(s)
	room := codeRowWidth(s) - 1 - len(ind)
	also := alsoIn(c, o, s, room-display.Width(note)-3)
	switch {
	case note != "" && len(also) == 1 && o.Verbosity == 0:
		b.WriteString(ind + s.Warn(note) + "   " + s.Dim(also[0]) + "\n")
	default:
		if note != "" {
			b.WriteString(ind + s.Warn(note) + "\n")
		}
		for _, a := range also {
			if o.Verbosity >= 1 {
				a = "also in " + a
			}
			b.WriteString(ind + s.Dim(s.clip(a, room)) + "\n")
		}
	}
	return b.String()
}

// renderCredentialLine is the one-row form used for fixtures.
func renderCredentialLine(c *credential, group []*credential, s *Style) string {
	ind := indentFor(s)
	loc := placeLoc(c.places[0])
	if n := len(c.places) - 1; n > 0 {
		loc += fmt.Sprintf(" +%d", n)
	}
	if s.Width < tierCompact {
		return ind + c.title + "\n" + ind + s.Dim(s.clip(c.id+" "+loc, s.Width-len(ind))) + "\n"
	}
	titleW := 0
	for _, g := range group {
		titleW = max(titleW, display.Width(g.title))
	}
	titleW = min(titleW, 34) + 2
	idW := len(c.id) + 2
	for _, g := range group {
		idW = max(idW, len(g.id)+2)
	}
	line := ind + pad(s.clip(c.title, titleW-2), titleW) + pad(s.Dim(c.id), idW)
	return line + s.Path(s.clip(loc, max(10, codeRowWidth(s)-1-vis(line)))) + "\n"
}

func secretsNext(v secretView, o Options, s *Style) string {
	cmd := codeCommand(o)
	var steps []nextStep
	lead := append(append(append([]*credential{}, v.rotate...), v.fresh...), v.wait...)
	if len(lead) == 0 {
		lead = v.tests
	}
	if len(lead) > 0 {
		c := lead[0]
		why := "the credential, and the order to rotate it in"
		if n := len(c.places); n > 1 {
			why = fmt.Sprintf("the %d places it is written, and the order to rotate it in", n)
		}
		steps = append(steps, nextStep{cmd + " --explain " + c.id, why})
		for _, d := range lead[1:] {
			if d.id != c.id {
				steps = append(steps, nextStep{cmd + " --explain " + d.id, "the next credential to rotate"})
				break
			}
		}
	}
	if o.Verbosity == 0 {
		steps = append(steps, nextStep{cmd + " -v", "every place, with its line"})
	}
	if len(v.tests) > 0 {
		steps = append(steps, nextStep{cmd + " --show tests", "rank test fixtures with the rest"})
	}
	if dirs := vendoredDirsOf(v.vendored.vendored); len(dirs) > 0 {
		steps = append(steps, nextStep{cmd + " --exclude " + dirs[0].dir, "stop scanning code you did not write"})
	}
	return renderSteps(steps, s)
}

type nextStep struct{ cmd, why string }

// renderSteps draws a NEXT block.
func renderSteps(steps []nextStep, s *Style) string {
	if len(steps) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n " + s.Bold("NEXT") + "\n")
	w := 0
	for _, st := range steps {
		w = max(w, display.Width(st.cmd))
	}
	for _, st := range steps {
		if s.Width < tierCompact || 3+w+2+display.Width(st.why) > s.Width-1 {
			b.WriteString("   " + s.Cmd(st.cmd) + "\n")
			continue
		}
		b.WriteString("   " + pad(s.Cmd(st.cmd), w) + "  " + s.Dim(st.why) + "\n")
	}
	return b.String()
}

// explainSecret is --explain for a secrets rule: what it is, the order to
// rotate in, and where each copy sits and how it got there. The value is never
// shown, and neither is the line it is on, because the match span is unknown
// and a wrong guess at it would print the secret.
func explainSecret(hits []CodeFinding, o Options, s *Style) string {
	var b strings.Builder
	first := hits[0]
	creds := credentialsOf(hits)
	hits = nil
	for _, c := range creds {
		hits = append(hits, c.places...)
	}
	name := ruleTitle(first)
	fmt.Fprintf(&b, "\n %s  %s  %s\n", s.Bold(first.RuleID), s.Sev(first.Severity, s.G.Dot+" "+SevWord(first.Severity)), name)
	meta := []string{"secrets", fmt.Sprintf("%s in %s", plural(len(creds), "credential"), plural(len(hits), "place"))}
	var oldest *credential
	for _, c := range creds {
		if c.committed && (oldest == nil || c.at.Before(oldest.at)) {
			oldest = c
		}
	}
	if oldest != nil {
		if oldest.at.IsZero() {
			meta = append(meta, "committed")
		} else {
			meta = append(meta, "committed "+agoPhrase(o.Now, oldest.at))
		}
	}
	for _, c := range first.CWE {
		meta = append(meta, fmt.Sprintf("CWE-%d", c))
	}
	fmt.Fprintf(&b, " %s\n", s.Dim(strings.Join(meta, " "+s.G.Sep+" ")))

	if about := strings.TrimSpace(first.Description); about != "" || strings.TrimSpace(first.Message) != "" {
		if about == "" {
			about = strings.TrimSpace(first.Message)
		}
		b.WriteString("\n " + s.Bold("WHY IT MATTERS") + "\n")
		for _, l := range wrapText(about, s.Width-6) {
			b.WriteString("   " + l + "\n")
		}
	}

	b.WriteString("\n " + s.Bold("WHAT TO DO, IN THIS ORDER") + "\n")
	steps := rotationSteps(oldest, len(hits), o)
	for i, st := range steps {
		lines := wrapText(st, s.Width-8)
		for j, l := range lines {
			if j == 0 {
				fmt.Fprintf(&b, "   %d  %s\n", i+1, l)
			} else {
				b.WriteString("      " + l + "\n")
			}
		}
	}
	if first.HelpURI != "" {
		b.WriteString("   " + s.Dim("more ") + s.Cmd(first.HelpURI) + "\n")
	}

	var prod, tests []CodeFinding
	for _, h := range hits {
		if h.TestSuite {
			tests = append(tests, h)
		} else {
			prod = append(prod, h)
		}
	}
	section := func(title string, fs []CodeFinding) {
		if len(fs) == 0 {
			return
		}
		b.WriteString("\n " + s.Bold(title) + s.Dim(fmt.Sprintf(" %s %s %s the value is not shown", s.G.Sep, plural(len(fs), "place"), s.G.Sep)) + "\n")
		b.WriteString(" " + s.Rule(s.Width-2) + "\n")
		files := ruleFiles(fs)
		byFile := map[string][]CodeFinding{}
		for _, f := range fs {
			byFile[f.Path] = append(byFile[f.Path], f)
		}
		limit := len(files)
		if o.Verbosity == 0 {
			limit = min(limit, 6)
		}
		for i, f := range files[:limit] {
			if i > 0 {
				b.WriteString("\n")
			}
			b.WriteString("   " + s.Path(s.clip(f.path, s.Width-6)) + "\n")
			ps := byFile[f.path]
			sort.SliceStable(ps, func(a, c int) bool { return ps[a].Line < ps[c].Line })
			for _, p := range ps {
				line := fmt.Sprintf("%4s %s ", lineLabel(p.Line), s.G.Bar)
				status := s.Dim("history unknown")
				switch {
				case p.Committed:
					sha := p.Commit
					if len(sha) > 7 {
						sha = sha[:7]
					}
					when := ""
					if !p.CommittedAt.IsZero() {
						when = " " + s.G.Sep + " " + p.CommittedAt.Format("2006-01-02")
					}
					label := "committed"
					if p.InHistory {
						label = "in git history, committed"
					}
					status = s.Warn(label + " " + sha + when)
				case p.Blamed:
					status = s.Hot("not committed")
				}
				b.WriteString("      " + s.Dim(line) + status + "\n")
			}
		}
		if rest := len(files) - limit; rest > 0 {
			b.WriteString("\n   " + s.Dim(fmt.Sprintf("+ %d more %s %s add -v to list every one", rest, pluralWord(rest, "file", "files"), s.G.Sep)) + "\n")
		}
	}
	section("WHERE", prod)
	section("IN TESTS", tests)
	return b.String()
}

func lineLabel(n int) string {
	if n <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d", n)
}

// rotationSteps are the same for every credential, so they come from the kind
// of finding and not from per-rule metadata.
func rotationSteps(oldest *credential, places int, o Options) []string {
	if oldest == nil {
		return []string{
			"Remove the value from the file and load it from an environment variable or your secrets manager.",
			"If it was ever committed, pushed or shared, revoke it at the provider: removing the line does not revoke it.",
			"Issue a replacement into your secrets manager or CI secret store.",
		}
	}
	sha := oldest.commit
	if len(sha) > 7 {
		sha = sha[:7]
	}
	return []string{
		"Revoke the credential at the provider. Deleting the line does not revoke it.",
		logsStep(oldest, sha),
		"Issue a replacement into your secrets manager or CI secret store.",
		fmt.Sprintf("Remove it from the %s below. Once it is revoked, rewriting history is optional.", plural(places, "place")),
	}
}

// dedupePlaces drops a past-commit copy of a line that is also in the working
// tree: it is the same place, and the working copy is the one to edit.
func dedupePlaces(ps []CodeFinding) []CodeFinding {
	live := map[string]bool{}
	for _, p := range ps {
		if !p.InHistory {
			live[fmt.Sprintf("%s:%d", p.Path, p.Line)] = true
		}
	}
	var out []CodeFinding
	seen := map[string]bool{}
	for _, p := range ps {
		key := fmt.Sprintf("%s:%d", p.Path, p.Line)
		if p.InHistory && live[key] {
			continue
		}
		if seen[key+fmt.Sprint(p.InHistory, p.Commit)] {
			continue
		}
		seen[key+fmt.Sprint(p.InHistory, p.Commit)] = true
		out = append(out, p)
	}
	return out
}

// credLoc is a place as the secrets report names it.
func credLoc(p CodeFinding) string {
	loc := placeLoc(p)
	if p.InHistory {
		sha := p.Commit
		if len(sha) > 7 {
			sha = sha[:7]
		}
		loc += " (history " + sha + ")"
	}
	return loc
}

func logsStep(oldest *credential, sha string) string {
	if oldest.at.IsZero() {
		return fmt.Sprintf("Check the provider's access logs since %s committed it.", sha)
	}
	return fmt.Sprintf("Check the provider's access logs from %s on: %s committed it then.", oldest.at.Format("2006-01-02"), sha)
}
