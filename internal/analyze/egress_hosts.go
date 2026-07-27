package analyze

// What counts as an egress domain.
//
// A hostname written down in a repository is one of two things: somewhere the
// build or the running code CONNECTS TO, or an identifier that merely looks like
// a host — an XML namespace, a licence URL, a doc link, a Go module path. Only
// the first is egress, and telling them apart is the whole of this file.
//
// Three gates, in order of how much they throw away:
//
//  1. Shape. Two or more labels, an alphabetic last label, DNS-legal throughout.
//  2. TLD. The last label must be a real IANA delegation, which is what stops
//     `yaml.v3`, `core.min.js` and `settings.local.json` reading as hosts.
//  3. Meaning. Reserved names (RFC 2606/6761, RFC 8375) can never be reached, and
//     a curated denylist covers the hosts that appear in source as identifiers
//     rather than destinations.
//
// A dependency has a fourth gate: its PURL type must not be a registry. A package
// is fetched from its registry no matter what it is called, so `socket.io` stays a
// dependency while `pkg:golang/viperhappenscope.com` — resolved by asking DNS for
// that host — becomes egress.

import (
	_ "embed"
	"strings"
)

// The IANA delegation list, lowercased. Refreshed by `just sync-tlds`; the first
// line is IANA's own version stamp, which is why the parser skips comments.
//
//go:embed data/tlds.txt
var tldData string

var validTLDs = func() map[string]bool {
	out := make(map[string]bool, 1500)
	for line := range strings.SplitSeq(tldData, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[line] = true
	}

	return out
}()

// Names that resolve to nothing outside the machine or the test fixture that
// wrote them. RFC 2606 and RFC 6761 reserve most of these precisely so that they
// cannot be reached; `.internal` is RFC 8375's private-use zone.
var reservedHostSuffixes = []string{
	".local", ".localhost", ".internal", ".intranet", ".private", ".corp", ".home",
	".lan", ".test", ".invalid", ".example", ".arpa", ".onion",
}

var reservedHosts = map[string]bool{
	"localhost":   true,
	"example.com": true,
	"example.net": true,
	"example.org": true,
}

// Hosts that are written in source as identifiers, not destinations. An XML
// namespace is never fetched; a licence URL in a header comment is not egress;
// nobody's service calls Stack Overflow at runtime. Left in, they would be the
// most common "egress domain" in every repository and the count would mean
// nothing.
var nonEgressHosts = map[string]bool{
	"www.w3.org":                 true,
	"w3.org":                     true,
	"schemas.xmlsoap.org":        true,
	"schemas.microsoft.com":      true,
	"json-schema.org":            true,
	"spdx.org":                   true,
	"opensource.org":             true,
	"creativecommons.org":        true,
	"semver.org":                 true,
	"developer.mozilla.org":      true,
	"stackoverflow.com":          true,
	"pkg.go.dev":                 true,
	"godoc.org":                  true,
	"www.gnu.org":                true,
	"gnu.org":                    true,
	"www.apache.org":             true,
	"apache.org":                 true,
	"purl.org":                   true,
	"xmlns.com":                  true,
	"docs.oracle.com":            true,
	"tools.ietf.org":             true,
	"www.rfc-editor.org":         true,
	"datatracker.ietf.org":       true,
	"www.iso.org":                true,
	"www.unicode.org":            true,
	"unicode.org":                true,
	"www.ecma-international.org": true,
}

var nonEgressSuffixes = []string{".wikipedia.org", ".readthedocs.io"}

// PURL types whose packages come from a registry. The host in the name of one of
// these is a coincidence — npm resolves `socket.io` from the npm registry, and no
// DNS query for `socket.io` is ever made on its account.
var registryPurlTypes = map[string]bool{
	"npm": true, "pypi": true, "maven": true, "nuget": true, "cargo": true,
	"gem": true, "composer": true, "hex": true, "conan": true, "pub": true,
	"cran": true, "swift": true, "cocoapods": true, "deb": true, "rpm": true,
	"apk": true, "alpine": true, "docker": true, "oci": true, "huggingface": true,
}

// normaliseHost lowercases, drops a trailing root dot, a leading `www.` is KEPT
// (www.acme.io and acme.io are different names and may resolve differently), and
// strips anything that is not part of the name itself — port, userinfo, path.
func normaliseHost(raw string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	if _, after, ok := strings.Cut(h, "://"); ok {
		h = after
	}
	if _, after, ok := strings.Cut(h, "@"); ok {
		h = after
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if i := strings.Index(h, ":"); i >= 0 {
		h = h[:i]
	}

	return strings.TrimSuffix(h, ".")
}

// isHostShaped applies gate 1: DNS label rules, at least two labels, and a final
// label that is alphabetic. Written by hand rather than as one regex because the
// per-label rules (no leading or trailing hyphen, 63 bytes) are what reject the
// version strings and file names that a loose `\w+(\.\w+)+` would let through.
func isHostShaped(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}

	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}

	for i, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for j := 0; j < len(label); j++ {
			c := label[j]
			switch {
			case c >= 'a' && c <= 'z':
			case c >= '0' && c <= '9':
			case c == '-':
			default:
				return false
			}
		}

		// The TLD carries the whole burden of "is this a name at all", so it may
		// not be numeric: `10.0.0.1` is an address, not a domain, and an address
		// is not a DNS record.
		if i == len(labels)-1 {
			for j := 0; j < len(label); j++ {
				if label[j] < 'a' || label[j] > 'z' {
					return false
				}
			}
		}
	}

	return true
}

// isEgressHost is the full test. The input may be raw — a URL, a host:port, an
// email domain — because every caller has a different kind of string in hand.
func isEgressHost(raw string) bool {
	host := normaliseHost(raw)
	if !isHostShaped(host) {
		return false
	}

	labels := strings.Split(host, ".")
	if !validTLDs[labels[len(labels)-1]] {
		return false
	}

	if reservedHosts[host] || nonEgressHosts[host] {
		return false
	}
	for _, suffix := range reservedHostSuffixes {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	for _, suffix := range nonEgressSuffixes {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}

	return true
}

// TLDs people actually put services on: every two-letter ccTLD, plus the generic
// delegations that see real use.
//
// This is a SECOND, tighter gate, applied only where the evidence is weak — a
// bare dotted string with no scheme, no port and no call behind it. There, the
// full IANA list is too generous to be useful: `.total`, `.name`, `.data`,
// `.report`, `.direct`, `.host`, `.value` and `.prod` are all real delegations
// and all far likelier to be a metric id, a struct field or an expression
// reference than a destination. A URL, a port or a network call site skips this
// gate entirely, because those say what the string is for.
//
// Kept deliberately in step with the SQL in the saas migration
// 20260728000004_reclassify_egress_domain_nodes.
var commonNetworkTLDs = map[string]bool{
	"com": true, "org": true, "net": true, "edu": true, "gov": true, "mil": true,
	"int": true, "info": true, "biz": true, "pro": true, "mobi": true, "app": true,
	"dev": true, "cloud": true, "tech": true, "online": true, "site": true,
	"website": true, "space": true, "store": true, "shop": true, "blog": true,
	"wiki": true, "news": true, "media": true, "digital": true, "systems": true,
	"solutions": true, "services": true, "network": true, "software": true,
	"tools": true, "codes": true, "computer": true, "email": true, "host": true,
	"hosting": true, "link": true, "live": true, "ninja": true, "studio": true,
	"team": true, "works": true, "world": true, "xyz": true, "zone": true,
	"agency": true, "academy": true, "center": true, "company": true,
	"consulting": true, "group": true,
}

// isCommonNetworkTLD gates the weak-evidence paths. Two letters is every ccTLD,
// which is why it is a length test rather than another list.
func isCommonNetworkTLD(host string) bool {
	i := strings.LastIndex(host, ".")
	if i < 0 {
		return false
	}
	tld := host[i+1:]

	return len(tld) == 2 || commonNetworkTLDs[tld]
}

// purlType reads the type out of `pkg:<type>/<namespace>/<name>@<version>`.
func purlType(purl string) string {
	rest := strings.TrimPrefix(purl, "pkg:")
	if head, _, ok := strings.Cut(rest, "/"); ok {
		return strings.ToLower(head)
	}

	return ""
}

// egressHostFromDependency answers "is this dependency actually a hostname we
// resolve". It is deliberately narrow: only the name the graph would have shown,
// and only when the package did not come from a registry.
//
// The module path's OWN host is not harvested here. `github.com/spf13/viper` is
// hosted at github.com, but treating that as egress would make github.com the
// single busiest node in every estate while describing provenance rather than a
// destination this repository reaches for on its own account.
func egressHostFromDependency(purl, name string) (string, bool) {
	if registryPurlTypes[purlType(purl)] {
		return "", false
	}
	if !isEgressHost(name) {
		return "", false
	}

	return normaliseHost(name), true
}

// Where a host was written down. The class is what lets a reader tell "our CI
// downloads from here" from "a string literal in a test mentions it", which are
// the same regex match and very different facts.
const (
	egressSourceCI        = "ci"
	egressSourceContainer = "container"
	egressSourceIaC       = "iac"
	egressSourceEnv       = "env"
	egressSourceManifest  = "manifest"
	egressSourceConfig    = "config"
	egressSourceCode      = "code"
)

// classifyEgressSource maps a repo-relative path to its source class. Order
// matters: a `.tf` file inside `.github/` is still infrastructure, but a workflow
// is a workflow whatever it is called.
func classifyEgressSource(path string) string {
	p := strings.ToLower(strings.TrimPrefix(path, "./"))
	base := p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		base = p[i+1:]
	}

	switch {
	case strings.HasPrefix(p, ".github/workflows/"),
		strings.HasPrefix(p, ".github/actions/"),
		strings.HasPrefix(base, ".gitlab-ci"),
		strings.HasPrefix(base, "azure-pipelines"),
		strings.HasPrefix(p, ".circleci/"),
		strings.HasPrefix(p, ".buildkite/"),
		base == "jenkinsfile", base == "cloudbuild.yaml", base == "cloudbuild.yml":
		return egressSourceCI

	case strings.HasPrefix(base, "dockerfile"), strings.HasPrefix(base, "containerfile"),
		strings.HasSuffix(base, ".dockerfile"),
		strings.HasPrefix(base, "docker-compose"), strings.HasPrefix(base, "compose."):
		return egressSourceContainer

	case strings.HasSuffix(base, ".tf"), strings.HasSuffix(base, ".tfvars"),
		strings.HasSuffix(base, ".hcl"), strings.HasSuffix(base, ".nix"),
		strings.HasPrefix(p, "k8s/"), strings.HasPrefix(p, "kubernetes/"),
		strings.HasPrefix(p, "helm/"), strings.HasPrefix(p, "charts/"),
		strings.HasPrefix(p, "terraform/"), strings.HasPrefix(p, "deploy/"),
		base == "values.yaml", base == "values.yml", base == "serverless.yml",
		base == "template.yaml", base == "template.yml":
		return egressSourceIaC

	case strings.HasPrefix(base, ".env"), strings.HasSuffix(base, ".env"):
		return egressSourceEnv

	case egressManifestFiles[base], strings.HasSuffix(base, ".lock"),
		strings.HasSuffix(base, ".lockb"):
		return egressSourceManifest

	// Settings files that are none of the above. Separate from `code` because a
	// host in a config file is a host somebody configured, and because the two
	// are read differently: config is scanned line-wide, code only inside string
	// literals.
	case egressConfigExtensions[fileExtension(base)]:
		return egressSourceConfig
	}

	return egressSourceCode
}

func fileExtension(base string) string {
	if i := strings.LastIndex(base, "."); i >= 0 {
		return base[i:]
	}

	return ""
}

// egressConfigExtensions are read even though they carry no tree-sitter
// language. This is where the CI, container and infrastructure hosts are.
var egressConfigExtensions = map[string]bool{
	".yaml": true, ".yml": true, ".json": true, ".toml": true, ".ini": true,
	".conf": true, ".cfg": true, ".properties": true, ".env": true, ".tf": true,
	".tfvars": true, ".hcl": true, ".nix": true, ".sh": true, ".bash": true,
	".zsh": true, ".ps1": true, ".xml": true, ".gradle": true,
}

var egressManifestFiles = map[string]bool{
	"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"npm-shrinkwrap.json": true, "composer.lock": true, "gemfile.lock": true,
	"poetry.lock": true, "pipfile.lock": true, "cargo.lock": true,
	"go.sum": true, "go.mod": true, "requirements.txt": true, "pyproject.toml": true,
	"gradle.lockfile": true, "packages.lock.json": true, "flake.lock": true,
}
