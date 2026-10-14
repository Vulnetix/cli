package scan

import (
	"fmt"
	"strings"

	"github.com/vulnetix/cli/v3/internal/versions"
)

// Verdict answers the question a finding row never answered on its own: is the
// version installed here actually affected?
//
// EnrichedVuln has carried VersionStatus and Confirmed for a long time, and the
// table printed neither. A row in a vulnerability table reads as "you are
// vulnerable", so a package whose installed version is already past the
// advisory's fix still looked like a finding, with nothing on the row to
// contradict it. Verdict is that missing sentence, computed once so every
// renderer, gate and explanation agrees.
type Verdict string

const (
	// VerdictAffected means the installed version is inside a range the advisory
	// supplied, or the source asserted it is affected and nothing contradicts it.
	VerdictAffected Verdict = "affected"
	// VerdictUnverified means the match was by package name and there is nothing
	// to compare the installed version with. Unknown is not safe, so it counts.
	VerdictUnverified Verdict = "unverified"
	// VerdictLikelyNotAffected means the evidence points away from the installed
	// version without proving it: no usable range, but installed is not older
	// than the fix, or a range excludes it while the source still flagged it.
	VerdictLikelyNotAffected Verdict = "likely_not_affected"
	// VerdictNotAffected means the installed version is outside every range the
	// advisory supplied, or the source said so explicitly.
	VerdictNotAffected Verdict = "not_affected"
)

// Counts reports whether a finding with this verdict counts toward gates and
// toward the "needs attention" totals. Unverified counts: an unknown is not a
// reason to pass a build.
func (v Verdict) Counts() bool {
	return v == VerdictAffected || v == VerdictUnverified || v == ""
}

// Label is the short human word for the verdict.
func (v Verdict) Label() string {
	switch v {
	case VerdictAffected:
		return "affected"
	case VerdictUnverified:
		return "unverified"
	case VerdictLikelyNotAffected:
		return "likely not affected"
	case VerdictNotAffected:
		return "not affected"
	}
	return string(v)
}

// VerdictResult is a verdict together with the working that produced it, so a
// reader can check the arithmetic rather than trust the word.
type VerdictResult struct {
	Verdict Verdict
	// Confidence is "high", "medium" or "low".
	Confidence string
	// Basis names the evidence: "range", "source", "recommended-fix", "none" or
	// "unparseable-version".
	Basis string
	// Installed is the version that was checked.
	Installed string
	// Range is the advisory's affected range, when it supplied one.
	Range string
	// FixedIn is the version the advisory (or, failing that, the recommendation)
	// names as the first safe one. FixedInSource says which.
	FixedIn       string
	FixedInSource string // "advisory" | "recommended"
	// AnyUpgradeClears is set when the range names only the installed version
	// itself ("= 2.19.1"), so moving to any other version clears the advisory.
	AnyUpgradeClears bool
	// MatchedBy is a plain-language statement of how the finding was matched.
	MatchedBy string
	// Detail is one sentence describing the comparison.
	Detail string
}

// EvaluateVerdict derives the verdict for one enriched finding. It is pure: no
// network, no settings, no mutation of its input.
func EvaluateVerdict(ev EnrichedVuln) VerdictResult {
	installed := ComparableVersion(ev.Ecosystem, ev.PackageVer)
	res := VerdictResult{
		Installed: installed,
		Range:     strings.TrimSpace(ev.AffectedRange),
		MatchedBy: "package name only",
	}

	status := versions.Status(strings.ToLower(strings.TrimSpace(ev.VersionStatus)))
	iv, parseErr := versions.Parse(installed)
	installedOK := installed != "" && parseErr == nil
	policy := versions.ResolvePseudoPolicy(versions.Options{Ecosystem: ev.Ecosystem})

	var rangeSet *versions.RangeSet
	if installedOK && res.Range != "" && !versions.IsWildcardRange(res.Range) {
		if rs, err := versions.ParseRange(res.Range); err == nil {
			rangeSet = &rs
		}
	}
	if rangeSet != nil {
		res.MatchedBy = "package name and version"
		if fixed := fixedInFromRange(*rangeSet, iv); fixed != "" {
			res.FixedIn = fixed
			res.FixedInSource = "advisory"
		}
	}

	// 1. An explicit "unaffected" from the source is the most specific thing it
	//    can say: the VEX-style exact-unaffected entry beats an affected range.
	if status == versions.StatusUnaffected {
		res.Verdict = VerdictNotAffected
		res.Confidence = "high"
		res.Basis = "source"
		res.MatchedBy = "package name and version"
		res.Detail = fmt.Sprintf("%s is listed as unaffected by the advisory.", orUnknown(installed))
		return res
	}

	// 2. Arithmetic on the supplied range. Reproducible, so it outranks a flag.
	if rangeSet != nil {
		contained := rangeSet.Contains(iv, policy)
		res.AnyUpgradeClears = contained && onlyEquals(*rangeSet)
		switch {
		case contained:
			res.Verdict = VerdictAffected
			res.Confidence = "high"
			res.Basis = "range"
			res.Detail = fmt.Sprintf("%s is inside %s.", installed, res.Range)
		case status == versions.StatusAffected:
			// The range excludes the install but the source flagged it. Two pieces
			// of evidence disagree, and neither is allowed to hide a finding: this
			// is unverified, which still counts. The advisory's record settles it
			// (ResolveUnverified). Treating it as "likely not affected" once hid real
			// nokogiri vulnerabilities behind a version-format quirk.
			res.Verdict = VerdictUnverified
			res.Confidence = "low"
			res.Basis = "conflict"
			res.Detail = fmt.Sprintf("%s is outside %s, but the source flagged it as affected. The two disagree, so it is not ruled out.", installed, res.Range)
		case newerThanEveryExactVersion(*rangeSet, iv):
			// The only thing the advisory states is a list of specific releases, and the
			// install is newer than all of them. A list like that is often a sample, not
			// the whole affected span: cve.org's own record for CVE-2024-6783 is
			// 2.0.0 through 2.7.16, and a copy that kept only "2.0.0" cleared 2.7.16, the
			// last affected release. It is not ruled out; the advisory's record settles it.
			res.Verdict = VerdictUnverified
			res.Confidence = "low"
			res.Basis = "conflict"
			res.Detail = fmt.Sprintf("The advisory lists only %s, and %s is newer. A list of specific releases may be a sample of the affected span, so this is not ruled out.", res.Range, installed)
		default:
			res.Verdict = VerdictNotAffected
			res.Confidence = "high"
			res.Basis = "range"
			res.Detail = fmt.Sprintf("%s is outside %s.", installed, res.Range)
		}
		return res
	}

	// 3. No usable range. If the install is not older than the version we would
	//    recommend, it has probably already passed the fix.
	if installedOK && ev.Remediation != nil && strings.TrimSpace(ev.Remediation.FixVersion) != "" {
		fix := strings.TrimSpace(ev.Remediation.FixVersion)
		if fv, err := versions.Parse(fix); err == nil && versions.Compare(iv, fv) >= 0 {
			res.Verdict = VerdictLikelyNotAffected
			res.Confidence = "medium"
			res.Basis = "recommended-fix"
			res.FixedIn = fix
			res.FixedInSource = "recommended"
			res.Detail = fmt.Sprintf("No usable affected range was supplied. %s is not older than %s, the first safe version.", installed, fix)
			return res
		}
	}

	// 4. A range exists and cannot be compared with a version. OSV records many
	//    PYSEC and Go advisories as git commit ranges. Calling that "affected"
	//    because a source flagged it would be a claim nobody checked, so it is
	//    unverified, and the reason is stated: that is the sentence that was
	//    missing when a package well past its fix still showed as a finding.
	if installedOK && res.Range != "" && rangeSet == nil && !versions.IsWildcardRange(res.Range) {
		res.Verdict = VerdictUnverified
		res.Confidence = "low"
		res.Basis = "range-not-comparable"
		if commit := commitInRange(res.Range); commit != "" {
			res.Detail = fmt.Sprintf("The advisory's range is a git commit (%s), which cannot be compared with version %s.", commit, installed)
		} else {
			res.Detail = fmt.Sprintf("The advisory's range %q could not be compared with version %s.", res.Range, installed)
		}
		return res
	}

	// 5. No range at all. An explicit "affected" from the source stands.
	if status == versions.StatusAffected || (status == "" && ev.Confirmed) {
		res.Verdict = VerdictAffected
		res.Confidence = "medium"
		res.Basis = "source"
		res.MatchedBy = "package name and version"
		res.Detail = fmt.Sprintf("The source reports %s as affected; it supplied no range to check.", orUnknown(installed))
		return res
	}

	res.Verdict = VerdictUnverified
	res.Confidence = "low"
	if installedOK {
		res.Basis = "none"
		res.Detail = "Matched by package name only; the advisory supplied no range to compare with."
	} else {
		res.Basis = "unparseable-version"
		res.Detail = fmt.Sprintf("The installed version %q could not be compared.", installed)
	}
	return res
}

// commitInRange returns the abbreviated git commit a range bound names, or "".
// A bound counts as a commit when it is at least seven hex digits and mixes
// letters in, which no real version string does.
func commitInRange(r string) string {
	for _, tok := range strings.FieldsFunc(r, func(c rune) bool {
		return strings.ContainsRune("<>=!~^ ,|[]()", c)
	}) {
		if len(tok) < 7 || len(tok) > 40 {
			continue
		}
		hasLetter, ok := false, true
		for _, c := range strings.ToLower(tok) {
			switch {
			case c >= 'a' && c <= 'f':
				hasLetter = true
			case c >= '0' && c <= '9':
			default:
				ok = false
			}
		}
		if ok && hasLetter {
			return tok[:7]
		}
	}
	return ""
}

// fixedInFromRange picks the exclusive upper bound that best answers "first
// safe version". When the install is below an upper bound that is the next fix;
// when it is above all of them it is the highest fix it has already passed.
func fixedInFromRange(rs versions.RangeSet, installed versions.Version) string {
	var above, below *versions.Version
	for _, r := range rs.Ranges {
		for _, c := range r.Constraints {
			if c.Op != versions.OpLt || c.Version.Wildcard {
				continue
			}
			cv := c.Version
			if versions.Compare(cv, installed) > 0 {
				if above == nil || versions.Compare(cv, *above) < 0 {
					v := cv
					above = &v
				}
			} else if below == nil || versions.Compare(cv, *below) > 0 {
				v := cv
				below = &v
			}
		}
	}
	switch {
	case above != nil:
		return above.Original
	case below != nil:
		return below.Original
	}
	return ""
}

func orUnknown(s string) string {
	if s == "" {
		return "the installed version"
	}
	return s
}

// onlyEquals reports whether every constraint in the set is an exact match.
func onlyEquals(rs versions.RangeSet) bool {
	n := 0
	for _, r := range rs.Ranges {
		for _, c := range r.Constraints {
			if c.Op != versions.OpEq {
				return false
			}
			n++
		}
	}
	return n > 0
}

// newerThanEveryExactVersion reports a range made only of exact versions, every one
// of which the installed version is newer than.
func newerThanEveryExactVersion(rs versions.RangeSet, installed versions.Version) bool {
	if !onlyEquals(rs) {
		return false
	}
	for _, r := range rs.Ranges {
		for _, c := range r.Constraints {
			if c.Version.Wildcard || versions.Compare(installed, c.Version) <= 0 {
				return false
			}
		}
	}
	return true
}
