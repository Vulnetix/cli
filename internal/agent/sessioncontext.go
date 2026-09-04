package agent

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/memory"
)

// maxPromptIDs caps how many advisories one prompt is answered about.
//
// A prompt that names thirty CVEs is pasting a report, not asking a question,
// and answering all thirty would bury the prompt it was attached to.
const maxPromptIDs = 5

// advisoryID matches the identifier forms someone actually types into a prompt.
//
// Deliberately not every scheme the VDB knows: an over-broad pattern turns
// ordinary prose into lookups, and a hook that fires on the word "go" is worse
// than one that misses RUSTSEC.
var advisoryID = regexp.MustCompile(`(?i)\b(CVE-\d{4}-\d{4,}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})\b`)

// sessionContext answers SessionStart and UserPromptSubmit.
//
// Both read what a previous scan already recorded rather than scanning now.
// This runs before the agent's turn, so the budget is a person waiting at a
// prompt; a scan here would be felt on every single message.
func (r Runner) sessionContext(_ context.Context, p Payload) Response {
	silent := Response{Event: p.HookEventName, Decision: Silent}

	switch p.HookEventName {
	case EventSessionStart:
		msg := r.repoRiskSummary()
		if msg == "" {
			return silent
		}
		return Response{Event: p.HookEventName, Decision: Inform, Message: msg}

	case EventUserPromptSubmit:
		// The cheap test first. Almost every prompt names no advisory at all,
		// and those must cost nothing beyond one regex.
		ids := advisoryIDsIn(p.UserPrompt())
		if len(ids) == 0 {
			return silent
		}
		msg := r.answerAdvisoryIDs(ids)
		if msg == "" {
			return silent
		}
		return Response{Event: p.HookEventName, Decision: Inform, Message: msg}
	}

	return silent
}

// advisoryIDsIn pulls the advisory identifiers out of a prompt, de-duplicated
// and in the order they were written.
func advisoryIDsIn(prompt string) []string {
	if prompt == "" {
		return nil
	}

	var out []string
	seen := map[string]bool{}

	for _, m := range advisoryID.FindAllString(prompt, -1) {
		// Case-fold to de-duplicate, but report the identifier as it was
		// written. The two schemes have opposite conventions — CVE-2021-44228
		// is upper, GHSA-jfh8-c2jp-5v3q is lower — so normalising the display
		// form gets one of them wrong whichever way it is chosen.
		key := strings.ToUpper(m)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, m)
		if len(out) == maxPromptIDs {
			break
		}
	}
	return out
}

// repoRiskSummary states what the last scan of this repository found.
//
// Read from the scan's own record rather than recomputed. That makes this
// honest about being a snapshot — it says when the scan was — instead of
// implying a freshness it did not pay for.
func (r Runner) repoRiskSummary() string {
	if r.Root == "" {
		return ""
	}

	mem, err := memory.Load(filepath.Join(r.Root, ".vulnetix"))
	if err != nil || mem == nil || mem.LastScan == nil {
		// No scan on record is worth one line: an agent that does not know a
		// scan is available will not suggest one.
		return "Vulnetix: no scan on record for this repository. `vulnetix scan` writes one."
	}

	last := mem.LastScan

	var b strings.Builder
	b.WriteString("Vulnetix: last scan of this repository")
	if last.Timestamp != "" {
		fmt.Fprintf(&b, " (%s", last.Timestamp)
		if last.GitBranch != "" {
			fmt.Fprintf(&b, ", %s", last.GitBranch)
		}
		b.WriteString(")")
	}
	fmt.Fprintf(&b, " found %d %s across %d %s",
		last.Vulns, plural(last.Vulns, "vulnerability", "vulnerabilities"),
		last.Packages, plural(last.Packages, "package", "packages"))

	if split := severitySplit(last); split != "" {
		fmt.Fprintf(&b, " — %s", split)
	}
	b.WriteString(".\n")

	if line := notableFindings(mem); line != "" {
		b.WriteString(line)
	}

	b.WriteString("\nThis is the recorded snapshot, not a scan run just now.")
	return b.String()
}

// severitySplit renders the counts the scan recorded, omitting the empty ones.
func severitySplit(s *memory.ScanRecord) string {
	var parts []string
	for _, p := range []struct {
		n     int
		label string
	}{
		{s.Critical, "critical"},
		{s.High, "high"},
		{s.Medium, "medium"},
		{s.Low, "low"},
	} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.label))
		}
	}
	return strings.Join(parts, ", ")
}

// notableFindings surfaces the two categories a version bump does not answer.
//
// Malicious entries are collapsed by package, not listed per advisory. The
// records are keyed by advisory id, so a package with six advisories against it
// appeared six times and the list read as six separate compromised
// dependencies.
func notableFindings(mem *memory.Memory) string {
	var kev []string
	maliciousSet := map[string]bool{}

	for id, f := range mem.Findings {
		if f.IsMalicious {
			maliciousSet[describeFinding(id, f)] = true
			continue
		}
		if f.InCisaKev {
			kev = append(kev, id)
		}
	}

	malicious := make([]string, 0, len(maliciousSet))
	for name := range maliciousSet {
		malicious = append(malicious, name)
	}

	sort.Strings(kev)
	sort.Strings(malicious)

	var b strings.Builder
	if len(malicious) > 0 {
		fmt.Fprintf(&b, "Malicious %s: %s\n",
			plural(len(malicious), "package", "packages"), joinCapped(malicious, 5))
	}
	if len(kev) > 0 {
		fmt.Fprintf(&b, "Known exploited: %s\n", joinCapped(kev, 5))
	}
	return b.String()
}

func describeFinding(id string, f memory.FindingRecord) string {
	if f.Package == "" {
		return id
	}
	return f.Package
}

// answerAdvisoryIDs reports what this repository already knows about the
// advisories a prompt named.
//
// Answered from the repository's own scan record, which makes the answer the
// useful one — whether it is here — rather than a restatement of the advisory
// the model can already recite. An identifier with no record gets one line
// saying exactly that, because "not in the last scan" is itself an answer and
// silence would read as "not affected".
func (r Runner) answerAdvisoryIDs(ids []string) string {
	if r.Root == "" {
		return ""
	}

	mem, err := memory.Load(filepath.Join(r.Root, ".vulnetix"))
	if err != nil || mem == nil {
		return ""
	}
	if mem.LastScan == nil {
		return ""
	}

	var b strings.Builder
	for _, id := range ids {
		f, ok := lookupFinding(mem, id)
		if !ok {
			fmt.Fprintf(&b, "  %s  not in this repository's last scan\n", id)
			continue
		}

		fmt.Fprintf(&b, "  %s  %s", id, findingSummary(f))
		b.WriteString("\n")
	}

	if b.Len() == 0 {
		return ""
	}

	return "Vulnetix, from this repository's last scan:\n" + b.String() +
		"\nFrom the recorded snapshot. `vulnetix scan` refreshes it."
}

// lookupFinding resolves an identifier against the record, following aliases.
//
// An advisory is filed under several identifiers and a prompt names whichever
// one the person saw. Matching only the key would answer "not in this scan"
// about a package the scan definitely found.
func lookupFinding(mem *memory.Memory, id string) (memory.FindingRecord, bool) {
	if f, ok := mem.Findings[id]; ok {
		return f, true
	}
	// The exact-key hit above is the fast path. Falling through to a scan also
	// covers the identifier being written in a different case from the one the
	// scan recorded, which a map lookup alone would miss.
	for key, f := range mem.Findings {
		if strings.EqualFold(key, id) {
			return f, true
		}
		for _, alias := range f.Aliases {
			if strings.EqualFold(alias, id) {
				return f, true
			}
		}
	}
	return memory.FindingRecord{}, false
}

// findingSummary is the one line an agent needs about a finding that is here.
func findingSummary(f memory.FindingRecord) string {
	var parts []string

	if f.Package != "" {
		pkg := f.Package
		if f.Versions != nil && f.Versions.Current != "" {
			pkg += "@" + f.Versions.Current
		}
		parts = append(parts, pkg)
	}
	if f.Severity != "" {
		parts = append(parts, strings.ToLower(f.Severity))
	}
	if f.IsMalicious {
		parts = append(parts, "MALICIOUS")
	}
	if f.InCisaKev {
		parts = append(parts, "known exploited")
	}
	if f.Status != "" {
		parts = append(parts, "status "+f.Status)
	}
	if f.Versions != nil && f.Versions.FixedIn != "" {
		parts = append(parts, "fixed in "+f.Versions.FixedIn)
	}

	if len(parts) == 0 {
		return "recorded, with no detail"
	}
	return strings.Join(parts, "  ")
}

func joinCapped(items []string, cap int) string {
	if len(items) <= cap {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:cap], ", "), len(items)-cap)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
