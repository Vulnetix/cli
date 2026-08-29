package license

import (
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// exceptions.go is the auditable escape hatch from a licence policy.
//
// Every real policy has exceptions — a vendored MPL-2.0 utility that counsel
// signed off, a GPL build tool that never ships. The question is whether the
// exception is recorded or whether somebody quietly widened the allow list. So
// an exception carries who approved it, when, on what grounds and until when,
// and an expired one stops applying and says so. An exception with no expiry is
// permitted, because some genuinely are permanent, but it is still attributed.
//
// Exempted findings are retained and badged, never dropped. A violation count
// that went down because somebody added an exception is a different fact from
// one that went down because the dependency was removed, and a report that
// cannot tell them apart is not an audit trail.

// ExceptionsAPIVersion is the apiVersion an exceptions document must declare.
const ExceptionsAPIVersion = "vulnetix.com/v1"

// ExceptionsKind is the kind an exceptions document must declare.
const ExceptionsKind = "LicenseExceptions"

// ExceptionSet is a collection of licence exceptions.
type ExceptionSet struct {
	APIVersion string `yaml:"apiVersion" json:"apiVersion"`
	Kind       string `yaml:"kind" json:"kind"`

	// Blanket exempts a licence everywhere it appears.
	Blanket []BlanketException `yaml:"blanket,omitempty" json:"blanket,omitempty"`
	// Packages exempts a specific package, optionally under a specific licence.
	Packages []PackageException `yaml:"packages,omitempty" json:"packages,omitempty"`
}

// BlanketException exempts a licence wherever it is found.
type BlanketException struct {
	// License is the SPDX id. Matching is by prefix, so an exception for
	// MPL-2.0 also covers MPL-2.0-no-copyleft-exception: they are the same
	// licence with a variation nobody writes a separate exception for.
	License   string `yaml:"license" json:"license"`
	Exception `yaml:",inline" json:",inline"`
}

// PackageException exempts one package.
type PackageException struct {
	// Purl matches the package, with '*' as a wildcard segment. A glob is the
	// useful form: an organisation vendoring every hashicorp module writes
	// pkg:golang/github.com/hashicorp/* once rather than an entry per module.
	Purl string `yaml:"purl,omitempty" json:"purl,omitempty"`
	// Name matches the package name as a substring, for ecosystems where the
	// short name and the fully-qualified module path are both in use.
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
	// License narrows the exception to one licence. Empty exempts the package
	// whatever licence it turns out to carry, which is a broader claim and
	// should be rarer.
	License   string `yaml:"license,omitempty" json:"license,omitempty"`
	Exception `yaml:",inline" json:",inline"`
}

// Exception is the governance metadata every exception carries.
type Exception struct {
	// ID is a stable identifier for referring to this exception in a report.
	ID string `yaml:"id,omitempty" json:"id,omitempty"`
	// Reason is why the exception exists. Required: an exception nobody can
	// explain is indistinguishable from a mistake.
	Reason string `yaml:"reason" json:"reason"`
	// Scope narrows the claim, e.g. "vendored, unmodified, dynamically linked".
	Scope string `yaml:"scope,omitempty" json:"scope,omitempty"`
	// Approver is who signed it off.
	Approver string `yaml:"approver,omitempty" json:"approver,omitempty"`
	// ApprovedDate is when, as YYYY-MM-DD.
	ApprovedDate string `yaml:"approvedDate,omitempty" json:"approvedDate,omitempty"`
	// Expires is when the exception lapses, as YYYY-MM-DD. Empty never expires.
	Expires string `yaml:"expires,omitempty" json:"expires,omitempty"`
	// Projects limits the exception to named projects. Empty applies everywhere.
	Projects []string `yaml:"projects,omitempty" json:"projects,omitempty"`
}

// ExpiresAt parses Expires, returning the zero time when it never expires.
func (e Exception) ExpiresAt() (time.Time, error) {
	if e.Expires == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse("2006-01-02", e.Expires)
	if err != nil {
		return time.Time{}, fmt.Errorf("expires %q is not a YYYY-MM-DD date", e.Expires)
	}
	return t, nil
}

// Expired reports whether the exception has lapsed as of now.
//
// An expired exception is not a soft signal: the finding reverts to a
// violation. That is the whole reason an expiry is worth writing down — an
// exception that quietly outlives its review is the failure mode this is
// designed to prevent.
func (e Exception) Expired(now time.Time) bool {
	at, err := e.ExpiresAt()
	if err != nil || at.IsZero() {
		return false
	}
	// The expiry date is inclusive: an exception expiring on the 1st is valid
	// throughout the 1st and lapses at the start of the 2nd.
	return now.After(at.AddDate(0, 0, 1).Add(-time.Nanosecond))
}

// AppliesToProject reports whether the exception covers a project.
func (e Exception) AppliesToProject(project string) bool {
	if len(e.Projects) == 0 {
		return true
	}
	for _, p := range e.Projects {
		if strings.EqualFold(p, project) || p == "*" {
			return true
		}
	}
	return false
}

// LoadExceptions reads an exception set from a YAML file.
func LoadExceptions(path string) (*ExceptionSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	set, err := ParseExceptions(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return set, nil
}

// ParseExceptions parses an exception document.
func ParseExceptions(data []byte) (*ExceptionSet, error) {
	var set ExceptionSet
	if err := yaml.Unmarshal(data, &set); err != nil {
		return nil, err
	}
	if err := set.Validate(); err != nil {
		return nil, err
	}
	return &set, nil
}

// Validate checks an exception document for structural problems.
func (s *ExceptionSet) Validate() error {
	if s.APIVersion != "" && s.APIVersion != ExceptionsAPIVersion {
		return fmt.Errorf("unsupported apiVersion %q (expected %s)", s.APIVersion, ExceptionsAPIVersion)
	}
	if s.Kind != "" && s.Kind != ExceptionsKind {
		return fmt.Errorf("unsupported kind %q (expected %s)", s.Kind, ExceptionsKind)
	}
	for i, b := range s.Blanket {
		if b.License == "" {
			return fmt.Errorf("blanket[%d]: license is required", i)
		}
		if b.Reason == "" {
			return fmt.Errorf("blanket[%d] (%s): reason is required — an exception nobody can explain is indistinguishable from a mistake", i, b.License)
		}
		if _, err := b.ExpiresAt(); err != nil {
			return fmt.Errorf("blanket[%d] (%s): %w", i, b.License, err)
		}
	}
	for i, p := range s.Packages {
		if p.Purl == "" && p.Name == "" {
			return fmt.Errorf("packages[%d]: one of purl or name is required", i)
		}
		if p.Reason == "" {
			return fmt.Errorf("packages[%d] (%s): reason is required", i, firstNonEmptyStr(p.Purl, p.Name))
		}
		if _, err := p.ExpiresAt(); err != nil {
			return fmt.Errorf("packages[%d] (%s): %w", i, firstNonEmptyStr(p.Purl, p.Name), err)
		}
	}
	return nil
}

// Applied is a matched exception, with why it matched.
type Applied struct {
	// Exception is the governance metadata.
	Exception Exception
	// Kind is "blanket" or "package".
	Kind string
	// Match describes what the exception was written against.
	Match string
	// Expired reports that the exception has lapsed and did NOT apply.
	Expired bool
}

// Label renders a short attribution for terminal and report output.
func (a Applied) Label() string {
	parts := []string{a.Kind + " exception"}
	if a.Exception.ID != "" {
		parts = append(parts, a.Exception.ID)
	}
	if a.Exception.Approver != "" {
		parts = append(parts, "approved by "+a.Exception.Approver)
	}
	if a.Exception.Expires != "" {
		parts = append(parts, "expires "+a.Exception.Expires)
	}
	return strings.Join(parts, ", ")
}

// Match finds the exception covering a package, if any.
//
// Returns the applied exception and whether it exempts the finding. An expired
// exception is returned with Expired set and exempts nothing: the caller
// reports why the finding is live rather than leaving the user to wonder why
// their exception stopped working.
func (s *ExceptionSet) Match(pkg PackageLicense, project string, now time.Time) (Applied, bool) {
	if s == nil {
		return Applied{}, false
	}

	var expired *Applied

	for _, b := range s.Blanket {
		if !licensePrefixMatch(b.License, pkg.LicenseSpdxID) {
			continue
		}
		if !b.AppliesToProject(project) {
			continue
		}
		a := Applied{Exception: b.Exception, Kind: "blanket", Match: b.License}
		if b.Expired(now) {
			a.Expired = true
			if expired == nil {
				expired = &a
			}
			continue
		}
		return a, true
	}

	for _, p := range s.Packages {
		if !packageExceptionMatches(p, pkg) {
			continue
		}
		if !p.AppliesToProject(project) {
			continue
		}
		a := Applied{Exception: p.Exception, Kind: "package", Match: firstNonEmptyStr(p.Purl, p.Name)}
		if p.Expired(now) {
			a.Expired = true
			if expired == nil {
				expired = &a
			}
			continue
		}
		return a, true
	}

	if expired != nil {
		return *expired, false
	}
	return Applied{}, false
}

// Expiring returns exceptions lapsing within the given window, soonest first.
//
// An exception that expires without anyone noticing turns into a surprise red
// build. Being able to ask "what lapses in the next 30 days" is what makes the
// expiry a review cadence rather than a trap.
func (s *ExceptionSet) Expiring(now time.Time, within time.Duration) []Applied {
	if s == nil {
		return nil
	}
	cutoff := now.Add(within)
	var out []Applied

	consider := func(e Exception, kind, match string) {
		at, err := e.ExpiresAt()
		if err != nil || at.IsZero() {
			return
		}
		if at.After(cutoff) {
			return
		}
		out = append(out, Applied{Exception: e, Kind: kind, Match: match, Expired: e.Expired(now)})
	}
	for _, b := range s.Blanket {
		consider(b.Exception, "blanket", b.License)
	}
	for _, p := range s.Packages {
		consider(p.Exception, "package", firstNonEmptyStr(p.Purl, p.Name))
	}

	// Soonest first, so the list reads as a work queue.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Exception.Expires < out[j-1].Exception.Expires; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// licensePrefixMatch reports whether an exception's licence covers an id.
//
// Prefix, not equality: MPL-2.0 and MPL-2.0-no-copyleft-exception are the same
// licence with a variation, and requiring a separate exception for each variant
// spelling would mean an exception that silently stops applying when a
// dependency's metadata gets more precise.
func licensePrefixMatch(exceptionLicense, spdxID string) bool {
	if exceptionLicense == "" || spdxID == "" {
		return false
	}
	e := strings.ToLower(NormalizeSPDX(exceptionLicense))
	got := strings.ToLower(NormalizeSPDX(spdxID))
	return got == e || strings.HasPrefix(got, e+"-") || strings.HasPrefix(got, e+"+")
}

// packageExceptionMatches reports whether an exception covers a package.
func packageExceptionMatches(e PackageException, pkg PackageLicense) bool {
	if e.License != "" && !licensePrefixMatch(e.License, pkg.LicenseSpdxID) {
		return false
	}
	if e.Purl != "" {
		if !purlGlobMatch(e.Purl, pkg) {
			return false
		}
		return true
	}
	if e.Name != "" {
		return packageNameMatches(e.Name, pkg.PackageName)
	}
	return false
}

// packageNameMatches reports whether an exception's name covers a package name.
//
// Path-segment matching, NOT substring. The short name and the fully-qualified
// module path are both in circulation, so an exception written for "golang-lru"
// must cover "github.com/hashicorp/golang-lru" — but a substring test also makes
// an exception for "gpl-lib" silently cover "agpl-lib", which is a different and
// stricter licence. An exception that quietly covers more than it names is the
// worst failure this file can have, so the match is anchored at a segment
// boundary: equal, or the final path segment, or a trailing "/name" suffix.
func packageNameMatches(exceptionName, packageName string) bool {
	want := strings.ToLower(strings.TrimSpace(exceptionName))
	got := strings.ToLower(strings.TrimSpace(packageName))
	if want == "" || got == "" {
		return false
	}
	if want == got {
		return true
	}
	// npm scopes use "@scope/name"; module paths use "host/org/name". Both are
	// slash-separated, so one rule serves them.
	return strings.HasSuffix(got, "/"+want)
}

// purlGlobMatch matches a purl pattern against a package.
//
// The pattern is matched against the package's purl with the version stripped,
// so an exception does not silently lapse the next time the dependency is
// bumped — which would be the opposite of an auditable process.
func purlGlobMatch(pattern string, pkg PackageLicense) bool {
	candidate := packagePurl(pkg)
	if candidate == "" {
		return false
	}
	pattern = stripPurlVersion(pattern)
	if !strings.ContainsAny(pattern, "*?[") {
		return strings.EqualFold(pattern, candidate)
	}
	ok, err := path.Match(strings.ToLower(pattern), strings.ToLower(candidate))
	return err == nil && ok
}

// packagePurl renders a package's versionless purl.
func packagePurl(pkg PackageLicense) string {
	if pkg.Ecosystem == "" || pkg.PackageName == "" {
		return ""
	}
	return fmt.Sprintf("pkg:%s/%s", strings.ToLower(pkg.Ecosystem), pkg.PackageName)
}

// stripPurlVersion removes the version, qualifiers and subpath from a purl.
func stripPurlVersion(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	at := strings.LastIndex(p, "@")
	if at > strings.LastIndex(p, "/") {
		return p[:at]
	}
	return p
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// MarshalYAML renders the exception set as a YAML document.
func (s *ExceptionSet) MarshalYAML() ([]byte, error) {
	if s.APIVersion == "" {
		s.APIVersion = ExceptionsAPIVersion
	}
	if s.Kind == "" {
		s.Kind = ExceptionsKind
	}
	return yaml.Marshal(s)
}
