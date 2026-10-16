package report

import (
	"sort"
	"strings"
)

// Every command this package suggests is built here, so a suggestion carries
// what reproducing it needs: the narrowest scanner that finds the finding, the
// rule pack that supplied the rule, and the input flags (--path, --exclude...)
// the run was given. A suggestion that drops any of them names a finding the
// command it prints cannot see.

// command is the subcommand this run was, "scan" when unnamed.
func (o Options) command() string {
	if c := strings.TrimSpace(o.Command); c != "" {
		return c
	}
	return "scan"
}

// codeScanner is the scanner that owns a rule of this kind. `scan` runs every
// kind, so explaining one rule through it would run the others too.
func codeScanner(kind string, o Options) string {
	switch strings.ToLower(kind) {
	case "sast":
		return "sast"
	case "secrets":
		return "secrets"
	case "iac":
		return "iac"
	case "oci", "container", "containers":
		return "containers"
	}
	return o.command()
}

// packageScanner is the scanner that owns a dependency finding. A container
// scan's packages come from images `sca` does not read, and the replay
// commands explain from memory without asking the API anything, so those keep
// their own name.
func packageScanner(o Options) string {
	switch c := o.command(); c {
	case "containers", "report", "defend":
		return c
	}
	return "sca"
}

// strictCommand is the gating run that counts an advisory the scan ruled
// likely not affected. The replay commands do not gate, so it is `sca` there.
func strictCommand(o Options) string {
	scanner := packageScanner(o)
	if scanner == "report" || scanner == "defend" {
		scanner = "sca"
	}
	return rerunAs(o, scanner, "--strict")
}

// rerunCommand repeats this run with extra arguments: every pack it loaded and
// every input flag it was given.
func rerunCommand(o Options, extra ...string) string {
	return rerunAs(o, o.command(), extra...)
}

// rerunAs is rerunCommand on another scanner, carrying the flags it takes.
func rerunAs(o Options, scanner string, extra ...string) string {
	var packs []string
	if scanner == o.command() {
		for _, p := range o.RulePacks {
			packs = append(packs, p)
		}
	}
	return buildCommand(scanner, packs, o.Replay[scanner], extra)
}

// explainCommand is the command that explains query: the scanner that owns it,
// the packs that supplied ruleIDs, and the input flags the scanner takes.
func explainCommand(o Options, scanner, query string, ruleIDs ...string) string {
	var packs []string
	for _, id := range ruleIDs {
		packs = append(packs, o.RulePacks[strings.ToUpper(id)])
	}
	return buildCommand(scanner, packs, o.Replay[scanner], []string{"--explain", query})
}

func buildCommand(scanner string, packs, replay, extra []string) string {
	parts := []string{"vulnetix", scanner}
	seen := map[string]bool{}
	var uniq []string
	for _, p := range packs {
		if p != "" && !seen[p] {
			seen[p] = true
			uniq = append(uniq, p)
		}
	}
	sort.Strings(uniq)
	for _, p := range uniq {
		parts = append(parts, "--rule", p)
	}
	parts = append(parts, replay...)
	parts = append(parts, extra...)
	for i, p := range parts {
		parts[i] = shellQuote(p)
	}
	return strings.Join(parts, " ")
}

// shellQuote quotes a word a POSIX shell would split or expand, so a printed
// command can be pasted as it is: --exclude 'testdata/**'.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@%+=:,./_-", r)) {
			return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return s
}
