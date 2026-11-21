// Package brand selects which brand the CLI speaks for: Vulnetix
// (vulnetix.com, the default) or Vulnesis (vulnes.is).
//
// The brand is chosen at run time by the VULNETIX_BRAND environment variable
// (VULNESIS_BRAND is an alias): "vulnetix" or "vulnesis", in any case. Anything
// else, or nothing, is Vulnetix, so a released binary behaves exactly as it
// always has unless the user opts in.
//
// Code that builds or shows a vulnetix.com endpoint or link passes it through
// URL (or Host for a bare hostname). Under Vulnetix both are the identity.
// Under Vulnesis a vulnetix.com host maps onto vulnes.is:
//
//	vulnetix.com          -> vulnes.is
//	www.vulnetix.com      -> www.vulnes.is
//	api.vdb.vulnetix.com  -> api-vdb.vulnes.is
//
// No other host changes, and nothing but the host changes.
package brand

import (
	"os"
	"regexp"
	"strings"
	"sync"
)

// Brand is one of the brands the CLI can speak for.
type Brand int

const (
	// Vulnetix is vulnetix.com, the default.
	Vulnetix Brand = iota
	// Vulnesis is vulnes.is.
	Vulnesis
)

// EnvVar selects the brand; AliasEnvVar is read when EnvVar is unset or empty.
const (
	EnvVar      = "VULNETIX_BRAND"
	AliasEnvVar = "VULNESIS_BRAND"
)

const (
	vulnetixDomain = "vulnetix.com"
	vulnesisDomain = "vulnes.is"
)

var (
	mu      sync.Mutex
	once    sync.Once
	current Brand
)

// Parse reads a brand name, case-insensitively and ignoring surrounding space.
// ok is false for anything that is not a brand, and b is then Vulnetix.
func Parse(s string) (b Brand, ok bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "vulnetix":
		return Vulnetix, true
	case "vulnesis":
		return Vulnesis, true
	}
	return Vulnetix, false
}

// FromEnv is the brand the environment selects, read now.
func FromEnv() Brand {
	v := os.Getenv(EnvVar)
	if strings.TrimSpace(v) == "" {
		v = os.Getenv(AliasEnvVar)
	}
	b, _ := Parse(v)
	return b
}

// Current is the brand of this process. The environment is read once, on the
// first call; Set and Reset change that.
func Current() Brand {
	mu.Lock()
	defer mu.Unlock()
	once.Do(func() { current = FromEnv() })
	return current
}

// Set fixes the brand for the rest of the process, overriding the environment.
func Set(b Brand) {
	mu.Lock()
	defer mu.Unlock()
	once.Do(func() {})
	current = b
}

// Reset forgets the brand, so the next Current reads the environment again.
// It exists for tests.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	once = sync.Once{}
	current = Vulnetix
}

// Name is the display name: "Vulnetix" or "Vulnesis".
func (b Brand) Name() string {
	if b == Vulnesis {
		return "Vulnesis"
	}
	return "Vulnetix"
}

// String is the lower-case name VULNETIX_BRAND takes.
func (b Brand) String() string {
	return strings.ToLower(b.Name())
}

// Domain is the brand's apex domain.
func (b Brand) Domain() string {
	if b == Vulnesis {
		return vulnesisDomain
	}
	return vulnetixDomain
}

// Host maps a hostname, optionally with a port, for the current brand.
func Host(h string) string { return Current().Host(h) }

// URL maps the host of an absolute URL for the current brand.
func URL(raw string) string { return Current().URL(raw) }

// Text maps every http(s) URL in free text for the current brand.
func Text(s string) string { return Current().Text(s) }

// Host maps a hostname, optionally with a port, for b. Under Vulnetix, and for
// any host that is not vulnetix.com or below it, h is returned unchanged.
func (b Brand) Host(h string) string {
	if b != Vulnesis || h == "" {
		return h
	}
	if strings.ContainsAny(h, "[]") || strings.Count(h, ":") > 1 {
		return h // an IPv6 literal, never ours
	}
	name, port := h, ""
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		name, port = h[:i], h[i:]
	}
	dot := ""
	if strings.HasSuffix(name, ".") {
		name, dot = name[:len(name)-1], "."
	}
	lower := strings.ToLower(name)
	switch {
	case lower == vulnetixDomain:
		return vulnesisDomain + dot + port
	case strings.HasSuffix(lower, "."+vulnetixDomain):
		sub := strings.TrimSuffix(lower, "."+vulnetixDomain)
		if sub == "" || strings.HasPrefix(sub, ".") || strings.HasSuffix(sub, ".") || strings.Contains(sub, "..") {
			return h
		}
		return strings.ReplaceAll(sub, ".", "-") + "." + vulnesisDomain + dot + port
	}
	return h
}

// URL maps the host of an absolute (or scheme-relative) URL for b. Scheme,
// userinfo, port, path, query and fragment are kept byte for byte; only the
// host changes, and only when it is vulnetix.com or below it. Anything that is
// not such a URL is returned unchanged.
func (b Brand) URL(raw string) string {
	if b != Vulnesis {
		return raw
	}
	start := authorityStart(raw)
	if start < 0 {
		return raw
	}
	end := len(raw)
	if i := strings.IndexAny(raw[start:], "/?#"); i >= 0 {
		end = start + i
	}
	authority := raw[start:end]
	hostStart := start
	if i := strings.LastIndexByte(authority, '@'); i >= 0 {
		hostStart = start + i + 1
	}
	hostport := raw[hostStart:end]
	if !validHostPort(hostport) {
		return raw
	}
	mapped := b.Host(hostport)
	if mapped == hostport {
		return raw
	}
	return raw[:hostStart] + mapped + raw[end:]
}

// authorityStart is the index just past "scheme://" (or a leading "//"), or -1.
func authorityStart(raw string) int {
	if strings.HasPrefix(raw, "//") {
		return 2
	}
	i := strings.Index(raw, "://")
	if i <= 0 {
		return -1
	}
	for j, c := range raw[:i] {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case j > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return -1
		}
	}
	return i + 3
}

// validHostPort accepts a DNS name with an optional numeric port: the only
// shape a vulnetix.com host can take. Anything else is left alone.
func validHostPort(hp string) bool {
	if hp == "" {
		return false
	}
	name := hp
	if i := strings.LastIndexByte(hp, ':'); i >= 0 {
		name = hp[:i]
		for _, c := range hp[i+1:] {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	if name == "" {
		return false
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.':
		default:
			return false
		}
	}
	return true
}

// urlInText finds http(s) URLs in prose: the scheme and the authority are
// enough, since only the host is rewritten.
var urlInText = regexp.MustCompile(`(?i)\bhttps?://[^\s/?#"'<>(),;\x60]+`)

// Text maps the host of every http(s) URL in s for b. Bare hostnames and
// non-URL identifiers (urn:tei:..., apiVersion vulnetix.com/v1) are untouched.
func (b Brand) Text(s string) string {
	if b != Vulnesis {
		return s
	}
	return urlInText.ReplaceAllStringFunc(s, b.URL)
}
