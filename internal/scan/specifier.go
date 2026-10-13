package scan

import (
	"regexp"
	"strings"
)

// nonVersionWords are specifiers package managers accept where a version goes and
// that name no release.
var nonVersionWords = map[string]bool{
	"latest": true, "next": true, "canary": true, "beta": true, "alpha": true, "rc": true,
	"dev": true, "stable": true, "nightly": true, "main": true, "master": true, "head": true,
	"*": true, "x": true, "any": true, "unspecified": true, "unknown": true, "none": true,
}

// nonVersionPrefixes are protocols and placeholders that stand in for a version:
// pnpm and yarn workspaces and catalogs, local links, git and URL dependencies,
// and Maven property references that were never resolved.
var nonVersionPrefixes = []string{
	"workspace:", "link:", "file:", "catalog:", "portal:", "patch:", "git+", "git:", "github:",
	"gitlab:", "bitbucket:", "http:", "https:", "ssh:", "npm:", "jsr:", "${", "$(", "{{", "<",
}

// IsResolvedVersion reports whether v names a concrete release that can be looked
// up. A specifier does not: "latest", "catalog:", "workspace:*", "link:../x",
// "${remoting.version}" and the empty string all describe a dependency nobody
// resolved, and querying one is worse than skipping it. A versionless query asks
// the database for every advisory the package has ever had, so an unresolved
// dependency used to be reported as carrying all of them.
func IsResolvedVersion(v string) bool {
	s := strings.TrimSpace(v)
	if s == "" {
		return false
	}
	l := strings.ToLower(s)
	if nonVersionWords[l] {
		return false
	}
	for _, p := range nonVersionPrefixes {
		if strings.HasPrefix(l, p) {
			return false
		}
	}
	// A range is a constraint, not a release. Maven writes them in brackets.
	if strings.HasPrefix(s, "[") || strings.HasPrefix(s, "(") {
		return false
	}
	if strings.ContainsAny(s, "^~|") || strings.HasPrefix(s, ">") || strings.Contains(s, " - ") {
		return false
	}
	// Something with no digit in it cannot be a release.
	return strings.ContainsAny(s, "0123456789")
}

var gemPlatformRe = regexp.MustCompile(`^(\d+(?:\.\d+)*(?:\.[A-Za-z0-9]+)*)-((?:x86|x64|arm|aarch|universal|java|jruby|mswin|mingw|darwin|linux|musl|truffle)[A-Za-z0-9_.-]*)$`)

// StripGemPlatform removes the platform suffix of a precompiled RubyGem
// ("1.19.1-x86_64-linux-gnu" is nokogiri 1.19.1 built for a platform). Advisories
// are written against 1.19.1, so keeping the suffix matched nothing.
func StripGemPlatform(v string) string {
	if m := gemPlatformRe.FindStringSubmatch(strings.TrimSpace(v)); m != nil {
		return m[1]
	}
	return v
}

// ComparableVersion is the version to compare against advisory ranges: the
// installed version with anything the ecosystem appends that is not part of the
// release removed. Today that is a RubyGem's platform suffix; left in, it reads
// as a pre-release and "1.19.1-x86_64-linux-gnu" falls outside "= 1.19.1", which
// hid real nokogiri advisories.
func ComparableVersion(ecosystem, v string) string {
	v = strings.TrimSpace(v)
	switch strings.ToLower(ecosystem) {
	case "gem", "rubygems", "ruby":
		return StripGemPlatform(v)
	}
	return v
}
