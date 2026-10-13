package versions

import (
	"regexp"
	"strconv"
	"strings"
)

// pep440Re matches the PEP 440 forms SemVer cannot read: a pre-release written
// without a hyphen (1.0.0rc1, 2.0a1, 1.0.0_beta2), a .devN suffix and a .postN
// suffix. The long spellings (alpha, beta, c, pre, preview) and the "_" and "."
// separators are accepted.
//
// A hyphen is deliberately not a separator. "1.0.0-rc1" and "1.0.0-1" are valid
// SemVer, which already parses them, and claiming them here would change the
// ordering of every SemVer pre-release.
var pep440Re = regexp.MustCompile(`^(?:(\d+)!)?(\d+(?:\.\d+)*)` +
	`(?:[._]?(alpha|a|beta|b|preview|pre|rc|c)[._]?(\d*))?` +
	`(?:[._]?(post|rev|r)[._]?(\d*))?` +
	`(?:[._]?(dev)[._]?(\d*))?` +
	`(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`)

// pep440ToSemver rewrites a PEP 440 version into the form Parse reads, keeping
// PEP 440's ordering: .dev < a < b < rc < final < .post.
//
//   - a pre-release becomes a SemVer pre-release whose first identifier sorts
//     alphabetically in PEP 440's order ("0dev" < "1a" < "2b" < "3rc"), followed
//     by its number as a numeric identifier;
//   - .postN becomes a fourth numeric segment, which Compare orders after the
//     patch, so 1.0.post1 sorts above 1.0 and below 1.0.1;
//   - an epoch is dropped. Versions with differing epochs are vanishingly rare
//     in advisory data, and ordering across them is not attempted.
//
// It reports false when s is not PEP 440 or is already plain SemVer.
func pep440ToSemver(s string) (string, bool) {
	l := strings.ToLower(strings.TrimSpace(s))
	m := pep440Re.FindStringSubmatch(l)
	if m == nil {
		return "", false
	}
	pre, preN, post, postN, dev, devN, local := m[3], m[4], m[5], m[6], m[7], m[8], m[9]
	if pre == "" && post == "" && dev == "" {
		return "", false // plain dotted numbers: Parse already handles them
	}

	core := strings.Split(m[2], ".")
	for len(core) < 3 {
		core = append(core, "0")
	}
	out := strings.Join(core, ".")

	if post != "" {
		n := postN
		if n == "" {
			n = "0"
		}
		// A post-release number of 0 still sorts above the release.
		k, _ := strconv.Atoi(n)
		out += "." + strconv.Itoa(k+1)
	}

	var ids []string
	switch pre {
	case "a", "alpha":
		ids = []string{"1a", num(preN)}
	case "b", "beta":
		ids = []string{"2b", num(preN)}
	case "rc", "c", "pre", "preview":
		ids = []string{"3rc", num(preN)}
	}
	if dev != "" && len(ids) == 0 {
		ids = []string{"0dev", num(devN)}
	}
	if len(ids) > 0 {
		out += "-" + strings.Join(ids, ".")
	}
	if local != "" {
		out += "+" + local
	}
	return out, true
}

func num(s string) string {
	if s == "" {
		return "0"
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return "0"
	}
	return strconv.Itoa(n)
}
