package tea

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// SupportedVersions are the TEA specification versions this client speaks,
// newest first. The first entry is the default: it is chosen whenever the
// publisher advertises it.
var SupportedVersions = []string{"1.0.0", "0.4.0"}

// Candidate is one (endpoint, version) pair a client can try.
type Candidate struct {
	Endpoint WellKnownEndpoint
	// Version is the version exactly as the publisher advertised it. The URL is
	// built from this string, so build metadata is preserved.
	Version string
	// Supported is the entry of the supported list it matched.
	Supported string
}

// Root is the base URL for every call under the candidate: <url>/v<version>.
func (c Candidate) Root() string {
	return strings.TrimRight(c.Endpoint.URL, "/") + "/v" + c.Version
}

// normaliseVersion reduces an advertised version to the value used for
// comparison. Build metadata is ignored, and a two part version from a lenient
// publisher ("0.4") reads as 0.4.0. A pre-release stays a pre-release, so it
// never equals a stable entry in the supported list.
func normaliseVersion(v string) (*semver.Version, bool) {
	v = strings.TrimSpace(v)
	if v == "" || v[0] == 'v' || v[0] == 'V' {
		return nil, false
	}
	core, _, _ := strings.Cut(v, "+")
	main, pre, hasPre := strings.Cut(core, "-")
	if strings.Count(main, ".") == 1 {
		main += ".0"
	}
	if hasPre {
		main += "-" + pre
	}
	parsed, err := semver.StrictNewVersion(main)
	if err != nil {
		return nil, false
	}
	return parsed, true
}

// RankCandidates orders everything a client could try against a discovery
// document, best first.
//
// The rules are the specification's: prefer the greatest version both sides
// support, break ties by the endpoint's priority (absent means 1), then by the
// order the publisher listed them. Every mutually supported version of every
// endpoint is a candidate, so the list also carries the fallbacks: the same
// endpoint at an older version comes after the other endpoints at the newer one.
//
// A pre-release never matches, because the supported list holds stable versions
// only. Pointing a user's tooling at a provider's beta API is not a decision to
// make on their behalf.
func RankCandidates(doc *WellKnown, supported []string) []Candidate {
	if doc == nil {
		return nil
	}
	type ranked struct {
		Candidate
		ver      *semver.Version
		priority float64
		order    int
	}

	want := make(map[string]string, len(supported))
	for _, s := range supported {
		if v, ok := normaliseVersion(s); ok {
			want[v.String()] = s
		}
	}

	var all []ranked
	for _, e := range doc.Endpoints {
		priority := 1.0
		if e.Priority != nil {
			priority = *e.Priority
		}
		for _, adv := range e.Versions {
			v, ok := normaliseVersion(adv)
			if !ok {
				continue
			}
			match, ok := want[v.String()]
			if !ok {
				continue
			}
			all = append(all, ranked{
				Candidate: Candidate{Endpoint: e, Version: adv, Supported: match},
				ver:       v,
				priority:  priority,
				order:     len(all),
			})
		}
	}

	sort.SliceStable(all, func(i, j int) bool {
		if c := all[i].ver.Compare(all[j].ver); c != 0 {
			return c > 0
		}
		if all[i].priority != all[j].priority {
			return all[i].priority > all[j].priority
		}
		return all[i].order < all[j].order
	})

	out := make([]Candidate, len(all))
	for i, r := range all {
		out[i] = r.Candidate
	}
	return out
}

// AdvertisedVersions is every distinct version a document offers, in the order
// first seen. It is what an error shows when nothing matched.
func AdvertisedVersions(doc *WellKnown) []string {
	if doc == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range doc.Endpoints {
		for _, v := range e.Versions {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}

var rootVersionRE = regexp.MustCompile(`/v(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)/?$`)

// VersionFromRoot reads the specification version out of a root URL such as
// https://host/tea/v1.0.0, normalised to major.minor.patch. A root without a
// full version segment (Vulnetix's own /tea/v1 alias, or a custom path) returns
// "": the version is not knowable from the URL alone.
func VersionFromRoot(root string) string {
	m := rootVersionRE.FindStringSubmatch(root)
	if m == nil {
		return ""
	}
	v, ok := normaliseVersion(m[1])
	if !ok {
		return ""
	}
	return v.String()
}
