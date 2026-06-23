package cyclonedx

import (
	"net/url"
	"strings"
)

// ParsePurl splits a Package URL into (ecosystem, fullName, version), matching
// vdb-api's shared.PurlComponents.Ecosystem()/FullName() semantics so the
// DB-backed vuln lookup keys identically to /v2/cli.sca.
//
//	pkg:golang/github.com%2Fcloudflare%2Fcircl@1.6.3 → ("golang", "github.com/cloudflare/circl", "1.6.3")
//	pkg:npm/%40scope%2Fpkg@1.0.0                      → ("npm", "@scope/pkg", "1.0.0")
//	pkg:github-actions/actions%2Fcheckout@v5          → ("github-actions", "actions/checkout", "v5")
func ParsePurl(purl string) (ecosystem, fullName, version string) {
	s := strings.TrimPrefix(purl, "pkg:")
	if s == purl || s == "" {
		return "", "", ""
	}
	// Drop subpath (#...) then qualifiers (?...): per the PURL spec both trail the
	// version (pkg:type/name@version?qualifiers#subpath), so they must be removed
	// before the version is split off — otherwise the version retains e.g.
	// "4.2?extension=tar.gz", which breaks version comparison downstream.
	if h := strings.IndexByte(s, '#'); h >= 0 {
		s = s[:h]
	}
	if q := strings.IndexByte(s, '?'); q >= 0 {
		s = s[:q]
	}
	// version (last @ — namespaces never contain @)
	if at := strings.LastIndex(s, "@"); at >= 0 {
		version = s[at+1:]
		s = s[:at]
	}
	ecoPart, namePart, ok := strings.Cut(s, "/")
	if !ok {
		return "", "", unescape(version)
	}
	ecosystem = ecosystemFromType(ecoPart)
	fullName = unescape(namePart)
	version = unescape(version)
	return ecosystem, fullName, version
}

func unescape(s string) string {
	if d, err := url.PathUnescape(s); err == nil {
		return d
	}
	return s
}

// ecosystemFromType mirrors vdb-api shared.PurlComponents.Ecosystem(): canonical
// ecosystems pass through, unknown types return verbatim (the DB lookup is
// case-insensitive on ecosystem).
func ecosystemFromType(t string) string {
	switch t {
	case "npm", "pypi", "maven", "cargo", "gem", "nuget", "golang",
		"composer", "deb", "rpm", "apk", "github", "hex", "pub", "swift", "cocoapods":
		return t
	case "docker", "oci":
		return "docker"
	default:
		return t
	}
}
