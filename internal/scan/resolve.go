package scan

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/vulnetix/cli/v3/internal/versions"
)

// AffectedFetcher returns the structured affected-version data for one advisory
// (the body of GET /v2/vuln/{id}/affected), narrowed to one package so a record
// that names hundreds of products still returns the one that matters.
type AffectedFetcher func(ctx context.Context, id, pkgName, ecosystem string) (map[string]any, error)

// AffectedQuery is one AffectedFetcher call: an advisory and a package.
type AffectedQuery struct {
	ID, PkgName, Ecosystem string
}

// AffectedAnswer is one AffectedQuery's answer, as AffectedFetcher would give it.
type AffectedAnswer struct {
	Data map[string]any
	Err  error
}

// AffectedBatchFetcher answers many AffectedQuery at once, in order. An item it
// could not answer (any error but not-found) is asked again on its own.
type AffectedBatchFetcher func(ctx context.Context, queries []AffectedQuery) []AffectedAnswer

// ResolveStats reports what a resolution pass did.
type ResolveStats struct {
	// Candidates is how many findings the pass tried to settle.
	Candidates int
	// Resolved is how many it settled either way.
	Resolved int
	// NotAffected is how many of those turned out not to affect the installed
	// version: false positives removed at the source.
	NotAffected int
	// Fetches is how many advisory records were requested.
	Fetches int
	// Failed is how many of those requests did not produce a record (an API error
	// or the time budget). Findings that depended on one keep the verdict they
	// arrived with, so a non-zero count means the pass was not complete.
	Failed int
}

// ResolveUnverified settles findings whose version could not be checked from the
// range the scan carried. That includes findings carried by a wildcard
// range, which are "affected" on a source's say-so and would otherwise stay
// vulnerable after the fix.
//
// The scan response surfaces a single affected range per finding, and for many
// advisories that is a git commit (OSV records most PYSEC advisories that way),
// which cannot be compared with a version. The advisory's full record usually
// carries the version ranges as well. PYSEC-2024-38 lists both a git range and
// "< 0.109.1", so a package already at 0.135.1 is plainly outside it, and
// without this pass it stayed an "unverified" finding forever.
//
// The pass fetches the record for each unverified advisory, and for its aliases
// when the record has no entry for this package, then evaluates the installed
// version against every comparable range. It only ever resolves; a finding it
// cannot settle is left exactly as it was.
func ResolveUnverified(ctx context.Context, vulns []EnrichedVuln, fetch AffectedFetcher, workers int) ResolveStats {
	return ResolveUnverifiedBatched(ctx, vulns, fetch, nil, workers)
}

// ResolveUnverifiedBatched is ResolveUnverified that sends each wave of lookups
// through batch, one request instead of one per advisory. Answers are used
// exactly as fetch's would be; an item the batch could not answer falls back to
// fetch, with its usual retry.
func ResolveUnverifiedBatched(ctx context.Context, vulns []EnrichedVuln, fetch AffectedFetcher, batch AffectedBatchFetcher, workers int) ResolveStats {
	var st ResolveStats
	if fetch == nil {
		return st
	}
	if workers < 1 {
		workers = 8
	}

	var critical, detail []int
	for i := range vulns {
		if needsResolution(vulns[i]) {
			critical = append(critical, i)
		} else if needsFixDetail(vulns[i]) {
			detail = append(detail, i)
		}
	}
	st.Candidates = len(critical) + len(detail)
	if st.Candidates == 0 {
		return st
	}

	cache := map[string]map[string]any{}
	var mu sync.Mutex
	key := func(id string, i int) string {
		return id + "\x00" + strings.ToLower(vulns[i].PackageName) + "\x00" + strings.ToLower(vulns[i].Ecosystem)
	}
	type req struct {
		id string
		i  int
	}
	// fetchBatched answers what it can of reqs in batch calls and records it in
	// cache exactly as fetchAll would; fetchAll then skips those and asks fetch
	// for the rest.
	fetchBatched := func(reqs []req) []req {
		var queries []AffectedQuery
		var keys []string
		seen := map[string]bool{}
		for _, r := range reqs {
			k := key(r.id, r.i)
			mu.Lock()
			_, have := cache[k]
			mu.Unlock()
			if have || seen[k] {
				continue
			}
			seen[k] = true
			queries = append(queries, AffectedQuery{ID: r.id, PkgName: vulns[r.i].PackageName, Ecosystem: vulns[r.i].Ecosystem})
			keys = append(keys, k)
		}
		if len(queries) == 0 || ctx.Err() != nil {
			return reqs
		}
		answers := batch(ctx, queries)
		mu.Lock()
		defer mu.Unlock()
		for j, a := range answers {
			if j >= len(keys) {
				break
			}
			switch {
			case a.Err == nil:
				cache[keys[j]] = a.Data
				st.Fetches++
			case notFoundErr(a.Err):
				cache[keys[j]] = nil
				st.Fetches++
			}
		}
		return reqs
	}
	fetchAll := func(reqs []req) {
		if batch != nil {
			reqs = fetchBatched(reqs)
		}
		var wg sync.WaitGroup
		sem := make(chan struct{}, workers)
		for _, r := range reqs {
			k := key(r.id, r.i)
			mu.Lock()
			_, have := cache[k]
			if !have {
				cache[k] = nil // reserved: never fetch the same record twice
				st.Fetches++
			}
			mu.Unlock()
			if have {
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(r req, k string) {
				defer wg.Done()
				defer func() { <-sem }()
				if ctx.Err() != nil {
					return
				}
				data, err := fetch(ctx, r.id, vulns[r.i].PackageName, vulns[r.i].Ecosystem)
				if err != nil && ctx.Err() == nil && !notFoundErr(err) {
					// One more try: a gateway hiccup should not decide a verdict.
					time.Sleep(300 * time.Millisecond)
					data, err = fetch(ctx, r.id, vulns[r.i].PackageName, vulns[r.i].Ecosystem)
				}
				if err != nil {
					if !notFoundErr(err) {
						mu.Lock()
						st.Failed++
						mu.Unlock()
					}
					return
				}
				mu.Lock()
				cache[k] = data
				mu.Unlock()
			}(r, k)
		}
		wg.Wait()
	}

	settled := map[int]bool{}
	run := func(candidates []int, detailOnly bool) {
		// commit writes a conclusion onto a finding.
		commit := func(i int, id string, res affectedResult) {
			ev := &vulns[i]
			// Two kinds of evidence disagree: a source says this version is
			// affected, and the record's stated ranges exclude it (or reach it only
			// through an open-ended "introduced 0"). Neither may hide the finding
			// and neither may confirm it. It is kept as the conflict it is: the
			// range excludes the install while the source's flag stays, which
			// computes to "unverified" and still counts.
			if (res.status == versions.StatusAffected && res.weak) ||
				(res.status == versions.StatusUnaffected && detailOnly) {
				ev.AffectedRange = res.rangeStr
				ev.VersionStatus = string(versions.StatusAffected)
				ev.Confirmed = true
				ev.MatchMethod = "conflict:" + id
				settled[i] = true
				return
			}
			switch res.status {
			case versions.StatusAffected:
				ev.AffectedRange = res.rangeStr
				ev.VersionStatus = string(versions.StatusAffected)
				ev.Confirmed = true
			case versions.StatusUnaffected:
				// Leave VersionStatus unknown so the verdict is computed from the
				// range itself, which keeps the fixed-in version it names.
				ev.AffectedRange = res.rangeStr
				ev.VersionStatus = string(versions.StatusUnknown)
				ev.Confirmed = false
				st.NotAffected++
			default:
				return
			}
			ev.MatchMethod = "verified:" + id
			settled[i] = true
			st.Resolved++
		}
		// apply settles a finding from the record of its own advisory id.
		apply := func(i int, id string) {
			commit(i, id, evaluateAffectedData(cache[key(id, i)], vulns[i].PackageName, vulns[i].Ecosystem, vulns[i].PackageVer))
		}

		// Wave one: the advisory ids the findings carry.
		var first []req
		for _, i := range candidates {
			if vulns[i].CveID != "" {
				first = append(first, req{vulns[i].CveID, i})
			}
		}
		fetchAll(first)
		for _, i := range candidates {
			apply(i, vulns[i].CveID)
		}

		// Wave two: for what is left, the aliases the record names. A CVE record often
		// carries no entry for the package at all while its PYSEC or GHSA twin carries
		// the versions.
		aliasOf := map[int][]string{}
		var second []req
		for _, i := range candidates {
			if settled[i] {
				continue
			}
			for _, a := range aliasesWithRanges(cache[key(vulns[i].CveID, i)], vulns[i].CveID) {
				aliasOf[i] = append(aliasOf[i], a)
				second = append(second, req{a, i})
			}
		}
		if len(second) > 0 {
			fetchAll(second)
			for _, i := range candidates {
				if settled[i] {
					continue
				}
				// Alias groups are not always clean: a group can hold another advisory
				// for the same package. So an alias may only CLEAR a finding when every
				// alias that names the package agrees; one that says affected keeps it.
				var affectedBy, clearedBy string
				var affectedRes, clearedRes affectedResult
				for _, a := range aliasOf[i] {
					res := evaluateAffectedData(cache[key(a, i)], vulns[i].PackageName, vulns[i].Ecosystem, vulns[i].PackageVer)
					switch res.status {
					case versions.StatusAffected:
						if affectedBy == "" || (affectedRes.weak && !res.weak) {
							affectedBy, affectedRes = a, res
						}
					case versions.StatusUnaffected:
						if clearedBy == "" {
							clearedBy, clearedRes = a, res
						}
					}
				}
				switch {
				case affectedBy != "":
					commit(i, affectedBy, affectedRes)
				case clearedBy != "":
					commit(i, clearedBy, clearedRes)
				}
			}
		}
	}
	// What decides a verdict goes first, so a slow backend or the time budget
	// costs fix detail and never a verdict.
	run(critical, false)
	run(detail, true)
	return st
}

// aliasesWithRanges returns the identifiers worth fetching for a record: the
// families that carry structured version ranges, the record's own id excluded.
func aliasesWithRanges(data map[string]any, self string) []string {
	if data == nil {
		return nil
	}
	list, _ := data["aliases"].([]any)
	// Families that carry structured version ranges, best first. The lists are
	// long and start with distribution advisories and unrelated CVEs, so taking
	// the first few would never reach the GHSA or PYSEC record that has them.
	priority := []string{"GHSA-", "PYSEC-", "GO-", "RUSTSEC-", "OSV-", "CVE-"}
	var out []string
	for _, p := range priority {
		for _, a := range list {
			s, _ := a.(string)
			if s == "" || strings.EqualFold(s, self) || !strings.HasPrefix(strings.ToUpper(s), p) {
				continue
			}
			out = append(out, s)
			if len(out) >= maxAliasLookups {
				return out
			}
		}
	}
	return out
}

// maxAliasLookups bounds the alias records fetched per finding.
const maxAliasLookups = 6

type affectedResult struct {
	status   versions.Status
	rangeStr string
	// weak marks an "affected" that rests only on open-ended ranges (introduced
	// "0") in a record that also gives bounded ranges, none of which contain the
	// version. "Introduced 0" is how a database writes "from the beginning, as far
	// as I know"; it does not outvote stated introduction versions. A release older
	// than every stated introduction is unverified, not affected. rangeStr then
	// holds only the bounded ranges.
	weak bool
}

// openStart reports whether a range entry has no stated start: "introduced 0".
func openStart(ve versions.VersionEntry) bool {
	v := strings.TrimSpace(ve.Version)
	return v == "" || v == "0" || v == "0.0" || v == "0.0.0" || v == "*" || strings.EqualFold(v, "x")
}

// neverFixedFromStart reports an explicit "introduced 0, never fixed": a start of zero with
// a wildcard upper bound. A bare wildcard version ("*") is a different, weaker claim and is
// not matched, and neither is a git range.
func neverFixedFromStart(ve versions.VersionEntry) bool {
	if strings.EqualFold(ve.VersionType, "git") {
		return false
	}
	wild := func(p *string) bool {
		if p == nil {
			return false
		}
		s := strings.TrimSpace(*p)
		return s == "*" || strings.EqualFold(s, "x")
	}
	v := strings.TrimSpace(ve.Version)
	zero := v == "" || v == "0" || v == "0.0" || v == "0.0.0"
	return zero && (wild(ve.LessThan) || wild(ve.LessThanOrEqual))
}

// evaluateAffectedData checks one installed version against the entries of an
// affected record that name this package.
//
// Affected wins over everything: one comparable entry containing the version is
// enough. "Not affected" needs positive evidence: at least one comparable entry
// for the package, and the version inside none of them. An entry that is only a
// git commit is not evidence either way, and neither is a record with no entry
// for the package.
func evaluateAffectedData(data map[string]any, pkgName, ecosystem, installed string) affectedResult {
	installed = ComparableVersion(ecosystem, installed)
	entries, _ := data["affected"].([]any)
	if len(entries) == 0 {
		return affectedResult{status: versions.StatusUnknown}
	}
	opt := versions.Options{Ecosystem: ecosystem}
	var rangeParts, boundedParts, exactParts []string
	seen := map[string]bool{}
	sawComparable, affected := false, false
	var affectedBounded, affectedOpen, hasBounded bool
	// openToEnd: the record says "introduced 0, never fixed" for this package.
	var openToEnd, hasFixRange bool
	seenBounded := map[string]bool{}

	for _, e := range entries {
		am, ok := e.(map[string]any)
		if !ok || !samePackage(am, pkgName, ecosystem) {
			continue
		}
		var usable, ranges []versions.VersionEntry
		for _, ve := range decodeVersionEntries(am) {
			if neverFixedFromStart(ve) {
				openToEnd = true
			}
			if !comparableEntry(ve, ecosystem) {
				continue
			}
			usable = append(usable, ve)
			if ve.LessThan != nil || ve.LessThanOrEqual != nil {
				ranges = append(ranges, ve)
				// comparableEntry has dropped wildcard bounds, so this range has a
				// real upper bound: a fix landed.
				hasFixRange = true
			} else {
				exactParts = appendUniq(exactParts, "= "+ve.Version, seen)
			}
		}
		if len(usable) == 0 {
			continue
		}
		sawComparable = true
		for _, ve := range usable {
			isRange := ve.LessThan != nil || ve.LessThanOrEqual != nil
			open := isRange && openStart(ve)
			if isRange && !open {
				hasBounded = true
			}
			if st, _ := versions.EvaluateStatus(installed, []versions.VersionEntry{ve}, "", opt); st == versions.StatusAffected {
				affected = true
				// An enumerated version (no bounds) is usually the expansion of an
				// open-ended range over the registry, so it corroborates nothing the
				// range did not already say. Only a bounded range is independent.
				if isRange && !open {
					affectedBounded = true
				} else {
					affectedOpen = true
				}
			}
		}
		if len(ranges) > 0 {
			rs, _ := versions.BuildRangeStrings(ranges, "")
			for _, part := range strings.Split(rs, "||") {
				if p := strings.TrimSpace(part); p != "" {
					rangeParts = appendUniq(rangeParts, p, seen)
				}
			}
			var bounded []versions.VersionEntry
			for _, ve := range ranges {
				if !openStart(ve) {
					bounded = append(bounded, ve)
				}
			}
			if len(bounded) > 0 {
				bs, _ := versions.BuildRangeStrings(bounded, "")
				for _, part := range strings.Split(bs, "||") {
					if p := strings.TrimSpace(part); p != "" {
						boundedParts = appendUniq(boundedParts, p, seenBounded)
					}
				}
			}
		}
	}

	// "Introduced 0, never fixed" is the whole statement when the record has no bounded
	// range for the package: any releases it lists beside it are that range spelled out
	// (a malware advisory names the versions it was seen in, and means all of them), so
	// they are not the complete list and cannot rule the install out. A bounded range is
	// different: it says a fix landed, and a wildcard must not override it.
	if openToEnd && !hasFixRange && !affected {
		return affectedResult{status: versions.StatusAffected, rangeStr: "*"}
	}
	if affected && !affectedBounded && affectedOpen && hasBounded && len(boundedParts) > 0 {
		return affectedResult{status: versions.StatusAffected, rangeStr: strings.Join(boundedParts, " || "), weak: true}
	}
	switch {
	case affected:
		parts := append([]string{}, rangeParts...)
		// An enumerated version is only part of the story when it is the install.
		parts = append(parts, "= "+installed)
		return affectedResult{status: versions.StatusAffected, rangeStr: strings.Join(parts, " || ")}
	case sawComparable:
		parts := rangeParts
		if len(parts) == 0 {
			parts = exactParts
			if len(parts) > 12 {
				parts = parts[:12]
			}
		}
		return affectedResult{status: versions.StatusUnaffected, rangeStr: strings.Join(parts, " || ")}
	}
	return affectedResult{status: versions.StatusUnknown}
}

func appendUniq(list []string, s string, seen map[string]bool) []string {
	if seen[s] {
		return list
	}
	seen[s] = true
	return append(list, s)
}

// comparableEntry reports whether a version entry can be compared with an
// installed version: not a git commit, and with a bound or version that parses.
func comparableEntry(e versions.VersionEntry, ecosystem string) bool {
	if strings.EqualFold(e.VersionType, "git") {
		return false
	}
	parses := func(s string) bool {
		s = strings.TrimSpace(s)
		if s == "" {
			return false
		}
		if s == "0" {
			return true
		}
		// A wildcard ("*", "x") parses but says nothing about where a fix landed:
		// some sources list every release as affected, and treating that as
		// evidence would override a precise range from a better one.
		// A bound with a local-version suffix ("5.2.1+echo.1") is a distribution's
		// rebuild, not a release of the project. Its "introduced 0" says nothing
		// about the upstream package.
		if strings.Contains(s, "+") && (strings.EqualFold(ecosystem, "pypi") || strings.EqualFold(ecosystem, "pip")) {
			return false
		}
		v, err := versions.Parse(s)
		return err == nil && !v.Wildcard && commitInRange(s) == ""
	}
	switch {
	case e.LessThan != nil:
		return parses(*e.LessThan)
	case e.LessThanOrEqual != nil:
		return parses(*e.LessThanOrEqual)
	}
	return parses(e.Version) && e.Version != "0"
}

// samePackage matches an affected entry to a package by name, folding the
// spellings an ecosystem treats as one (PyPI's -, _ and .), and by ecosystem
// when the entry states one.
func samePackage(am map[string]any, name, ecosystem string) bool {
	norm := func(eco, s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		if eco == "pypi" || eco == "pip" {
			s = strings.NewReplacer("_", "-", ".", "-").Replace(s)
		}
		return s
	}
	eco := strings.ToLower(ecosystem)
	if e := strings.ToLower(stringVal(am, "ecosystem")); e != "" && eco != "" && e != eco && !ecoSynonym(e, eco) {
		return false
	}
	want := norm(eco, name)
	for _, key := range []string{"packageName", "product"} {
		if got := norm(eco, stringVal(am, key)); got != "" && got == want {
			return true
		}
	}
	return false
}

func ecoSynonym(a, b string) bool {
	groups := [][]string{{"pypi", "pip", "python"}, {"golang", "go"}, {"gem", "rubygems", "ruby"}, {"cargo", "crates.io", "rust"}, {"composer", "packagist", "php"}}
	for _, g := range groups {
		ina, inb := false, false
		for _, x := range g {
			ina = ina || x == a
			inb = inb || x == b
		}
		if ina && inb {
			return true
		}
	}
	return false
}

// needsResolution reports whether a finding's version was not settled by a range
// the scan could compare. That is every unverified finding, and also every one
// that is "affected" only because a source said so: a wildcard range ("*",
// ">= 0") is that. A wildcard claims every release is affected and says nothing
// about where a fix landed, so a package long past the fix kept reporting
// vulnerable until the advisory's own record was read.
func needsResolution(ev EnrichedVuln) bool {
	if strings.TrimSpace(ev.PackageVer) == "" {
		return false
	}
	v := EvaluateVerdict(ev)
	switch v.Verdict {
	case VerdictUnverified:
		return true
	case VerdictAffected:
		return v.Basis == "source"
	}
	return false
}

// needsFixDetail reports whether a finding is established as affected but names
// no version that fixes it. The scan response often carries only "= <installed>"
// for these, so the package's recommended upgrade was computed from the other
// advisories on it and could land below the version that clears this one: the
// user upgrades and is still vulnerable. Reading the advisory's record names the
// fix.
func needsFixDetail(ev EnrichedVuln) bool {
	if strings.TrimSpace(ev.PackageVer) == "" {
		return false
	}
	v := EvaluateVerdict(ev)
	if v.Verdict != VerdictAffected || v.Basis != "range" {
		return false
	}
	return v.FixedInSource != "advisory" || reachedOnlyThroughOpenRange(ev.AffectedRange, ComparableVersion(ev.Ecosystem, ev.PackageVer))
}

// reachedOnlyThroughOpenRange reports whether a range matches the installed
// version solely through clauses with no lower bound ("< 1.11.23"), while the
// same range also holds bounded clauses (">= 1.11.0 < 1.11.23") that do not.
// That shape means a source wrote "introduced 0" for lack of a better answer
// next to another that knew the real introduction, and the version predates the
// real one. The advisory's record decides.
func reachedOnlyThroughOpenRange(rangeStr, installed string) bool {
	iv, err := versions.Parse(installed)
	if err != nil || strings.TrimSpace(rangeStr) == "" {
		return false
	}
	var openHit, boundedHit, anyBounded bool
	for _, part := range strings.Split(rangeStr, "||") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		rs, err := versions.ParseRange(part)
		if err != nil || len(rs.Ranges) == 0 {
			continue
		}
		hasLower, hasUpper := false, false
		for _, c := range rs.Ranges[0].Constraints {
			switch c.Op {
			case versions.OpGt, versions.OpGte:
				hasLower = true
			case versions.OpLt, versions.OpLte:
				hasUpper = true
			}
		}
		hit := rs.Contains(iv, versions.ResolvePseudoPolicy(versions.Options{}))
		switch {
		case hasUpper && !hasLower:
			openHit = openHit || hit
		case hasLower && hasUpper:
			anyBounded = true
			boundedHit = boundedHit || hit
		default:
			// An exact clause is a statement about this version, not a bound.
			boundedHit = boundedHit || hit
		}
	}
	return openHit && anyBounded && !boundedHit
}

// notFoundErr reports an answer that says the record does not exist, which is
// a result and not a failure to get one.
func notFoundErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "404") || strings.Contains(s, "not found")
}
