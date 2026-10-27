package report

import (
	"sort"
	"strings"
)

// foldAliases collapses advisories that are one vulnerability under several
// identifiers (CVE-2018-16487 and SNYK-JS-LODASH-73638 on the same lodash). A
// package listing both reads as two problems, and the reader has no way to know
// fixing one fixes the other.
//
// Two advisories fold only when one of them makes an unambiguous claim on the other
// (it lists the other as an alias and no second id of that family), they reached
// the same verdict and they are different kinds of identifier, so an alias group that
// wrongly holds a second vulnerability never hides one the scan found affecting
// the package while the other did not The advisory kept is the one that sorts first; the
// others' ids move to AlsoKnownAs, and their signals, KEV flag, exploit count
// and score are carried over so no urgency is lost. JSON, SARIF and the SBOM
// still hold every finding.
func foldAliases(in []Advisory) []Advisory {
	if len(in) < 2 {
		return in
	}
	parent := make([]int, len(in))
	families := make([]map[string]bool, len(in))
	index := map[string]int{} // advisory id (upper) -> position
	for i, a := range in {
		parent[i] = i
		families[i] = map[string]bool{idFamily(a.ID): true}
		index[strings.ToUpper(strings.TrimSpace(a.ID))] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	// Only an unambiguous statement links two advisories: one lists the other's id
	// as an alias and names no second id of that family. The server caps alias lists
	// at 20, so the CVE side of a SNYK/GMS twin often omits it; a polluted record
	// lists many ids of one family and so claims nothing. A shared third alias is how one polluted group chained six
	// distinct CVEs into one row, so it is not evidence. A group also holds at
	// most one identifier per family (one CVE, one GHSA, one PYSEC, one SNYK'
	// ...): two CVEs are two vulnerabilities whatever a group says.
	for i, a := range in {
		for _, al := range a.Ev.Aliases {
			j, ok := index[strings.ToUpper(strings.TrimSpace(al))]
			if !ok || j == i || in[j].Verdict.Verdict != a.Verdict.Verdict || !(claims(a, in[j].ID) || claims(in[j], a.ID)) {
				continue
			}
			ri, rj := find(i), find(j)
			if ri == rj || sharesFamily(families[ri], families[rj]) {
				continue
			}
			parent[ri] = rj
			for f := range families[ri] {
				families[rj][f] = true
			}
		}
	}
	groups := map[int][]int{}
	var roots []int
	for i := range in {
		r := find(i)
		if _, ok := groups[r]; !ok {
			roots = append(roots, r)
		}
		groups[r] = append(groups[r], i)
	}
	if len(roots) == len(in) {
		return in
	}
	out := make([]Advisory, 0, len(roots))
	for _, r := range roots {
		members := groups[r]
		sort.SliceStable(members, func(x, y int) bool {
			a, b := in[members[x]], in[members[y]]
			if ra, rb := idRank(a.ID), idRank(b.ID); ra != rb {
				return ra < rb
			}
			return advisoryLess(a, b)
		})
		keep := in[members[0]]
		for _, m := range members[1:] {
			o := in[m]
			keep.AlsoKnownAs = append(keep.AlsoKnownAs, o.ID)
			keep.KEV = keep.KEV || o.KEV
			if o.Exploits > keep.Exploits {
				keep.Exploits = o.Exploits
			}
			if o.CVSS > keep.CVSS {
				keep.CVSS = o.CVSS
			}
			keep.AnyUpgrade = keep.AnyUpgrade || o.AnyUpgrade
			keep.Signals = mergeSignals(keep.Signals, o.Signals)
			if keep.Fix == "" {
				keep.Fix, keep.FixSource = o.Fix, o.FixSource
			}
		}
		sort.Strings(keep.AlsoKnownAs)
		out = append(out, keep)
	}
	return out
}

func mergeSignals(a, b []Signal) []Signal {
	have := map[string]int{}
	for i, s := range a {
		have[s.Label] = i
	}
	for _, s := range b {
		if i, ok := have[s.Label]; ok {
			a[i].Strong = a[i].Strong || s.Strong
			continue
		}
		have[s.Label] = len(a)
		a = append(a, s)
	}
	return a
}

// advisoryNamed reports whether id is the advisory's own identifier or one it
// absorbed, so `--explain SNYK-…` still finds the finding shown as its CVE.
func advisoryNamed(a Advisory, id string) bool {
	if strings.EqualFold(a.ID, id) {
		return true
	}
	for _, o := range a.AlsoKnownAs {
		if strings.EqualFold(o, id) {
			return true
		}
	}
	return false
}

// idFamily names the kind of identifier: CVE, GHSA, PYSEC, GMS, GO, RUSTSEC,
// SNYK, ... Within a family two ids are two records, never one.
func idFamily(id string) string {
	up := strings.ToUpper(strings.TrimSpace(id))
	if i := strings.IndexByte(up, '-'); i > 0 {
		return up[:i]
	}
	return up
}

func sharesFamily(a, b map[string]bool) bool {
	for f := range a {
		if b[f] {
			return true
		}
	}
	return false
}

// claims reports whether a lists id as an alias and lists no other id of the same
// family: a precise statement, where a record that lists six CVEs names none of them.
func claims(a Advisory, id string) bool {
	fam, found, others := idFamily(id), false, 0
	for _, al := range a.Ev.Aliases {
		if idFamily(al) != fam {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(al), strings.TrimSpace(id)) {
			found = true
		} else {
			others++
		}
	}
	return found && others == 0
}

// idRank orders the identifier a folded row is named by: the canonical CVE, then
// the GitHub advisory, then the ecosystem databases, then the vendor and
// aggregator ids (GMS-, SNYK-, ECHO-, ...) that only restate them.
func idRank(id string) int {
	switch idFamily(id) {
	case "CVE":
		return 0
	case "GHSA":
		return 1
	case "PYSEC", "GO", "RUSTSEC", "OSV", "MAL", "GSD":
		return 2
	}
	return 3
}
