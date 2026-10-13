// Package defences describes what Vulnetix has built to protect a vulnerability
// that has no fix: virtual patches, which block a request at the edge, and
// countermeasures, which detect the exploit on a host.
//
// The two are different promises and never share a line of output. A virtual
// patch stops the request; a countermeasure tells you it happened. Everything in
// this package keeps that distinction in the type, so a renderer cannot blur it
// by accident.
//
// The data comes from the Vulnetix vulnerability database:
//
//	GET /v2/vuln/{id}/virtual-patches
//	GET /v2/vuln/{id}/countermeasures
//	GET /v2/virtual-patches/{uuid}/archive      (Pro)
//	GET /v2/countermeasures/{uuid}/archive      (Pro)
//
// Every tier receives counts and the per-kind breakdown. Rule bodies and the
// archive URLs are Pro. "A defence exists for your vulnerability" is the warning
// and is not withheld; the rule is the product. Summary reflects that split.
//
// The fetch is stubbed. Source is the seam: DefaultSource returns
// StateUnavailable for everything until the CLI wiring lands, and renderers treat
// that as "say nothing" rather than as "none exist". StaticSource is a working
// in-memory implementation for tests and previews.
package defences

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
)

// Lane is which of the two promises a defence makes.
type Lane string

const (
	// LaneBlock is a virtual patch: it stops the request.
	LaneBlock Lane = "block"
	// LaneDetect is a countermeasure: it tells you it happened.
	LaneDetect Lane = "detect"
)

// Kind is the rule format. The values are the database's own.
type Kind string

const (
	KindSnort      Kind = "SNORT"
	KindSuricata   Kind = "SURICATA"
	KindModSec     Kind = "MODSECURITY"
	KindNginx      Kind = "NGINX"
	KindAWSWAF     Kind = "AWS_WAF"
	KindCloudflare Kind = "CLOUDFLARE_WAF"
	KindRegexL7    Kind = "REGEX_L7"
	KindSigma      Kind = "SIGMA"
	KindYARA       Kind = "YARA"
	KindSTIX       Kind = "STIX"
	KindOpenIOC    Kind = "OPENIOC"
)

type kindInfo struct {
	name string
	lane Lane
	// flag is the value accepted by `defend --for`.
	flag string
	// file is the conventional filename suffix, matching the archive endpoint.
	file string
}

var kinds = map[Kind]kindInfo{
	KindCloudflare: {"Cloudflare WAF", LaneBlock, "cloudflare", "cloudflare-expression.txt"},
	KindAWSWAF:     {"AWS WAF", LaneBlock, "aws-waf", "wafv2-rule.json"},
	KindSnort:      {"Snort", LaneBlock, "snort", "local.rules"},
	KindSuricata:   {"Suricata", LaneBlock, "suricata", "suricata.rules"},
	KindModSec:     {"ModSecurity", LaneBlock, "modsecurity", "modsecurity.conf"},
	KindNginx:      {"nginx", LaneBlock, "nginx", "nginx-waf.conf"},
	KindRegexL7:    {"Layer 7 regex", LaneBlock, "regex", "pattern.txt"},
	KindSigma:      {"Sigma", LaneDetect, "sigma", "sigma.yml"},
	KindYARA:       {"YARA", LaneDetect, "yara", "rule.yar"},
	KindSTIX:       {"STIX 2.1", LaneDetect, "stix", "bundle.json"},
	KindOpenIOC:    {"OpenIOC", LaneDetect, "openioc", "ioc.xml"},
}

// LaneOf returns the lane a kind belongs to. An unknown kind is reported as
// detect: that is the weaker claim, so a format we do not recognise is never
// presented as something that blocks.
func LaneOf(k Kind) Lane {
	if i, ok := kinds[Kind(strings.ToUpper(string(k)))]; ok {
		return i.lane
	}
	return LaneDetect
}

// Name is the display name of a kind.
func Name(k Kind) string {
	if i, ok := kinds[Kind(strings.ToUpper(string(k)))]; ok {
		return i.name
	}
	return string(k)
}

// Flag is the `defend --for` spelling of a kind.
func Flag(k Kind) string {
	if i, ok := kinds[Kind(strings.ToUpper(string(k)))]; ok {
		return i.flag
	}
	return strings.ToLower(string(k))
}

// ParseFlag resolves a `defend --for` value to a kind.
func ParseFlag(s string) (Kind, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	for k, i := range kinds {
		if i.flag == s || strings.ToLower(string(k)) == s {
			return k, true
		}
	}
	return "", false
}

// FileName is the conventional name a rule of this kind is saved under.
func FileName(artifactID string, k Kind) string {
	if i, ok := kinds[Kind(strings.ToUpper(string(k)))]; ok {
		return artifactID + "-" + i.file
	}
	return artifactID + ".txt"
}

// State is what the CLI can truthfully say about a finding's defences. The five
// "no rules to show" states are separate on purpose: collapsing them would let
// "we did not ask" read as "there is nothing".
type State string

const (
	// StateAvailable means rules exist and their details came back (Pro).
	StateAvailable State = "available"
	// StateGated means rules exist and only their counts came back.
	StateGated State = "gated"
	// StateNone means the database was asked and has nothing published yet. It
	// never means "cannot be defended": the database does not record that an
	// exploit was judged unobservable, only that nothing was built.
	StateNone State = "none"
	// StateNotIndexed means the identifier is not one that can be looked up: it is
	// not shaped like an advisory id, or the database refused it as input.
	StateNotIndexed State = "not_indexed"
	// StateNotChecked means the lookup was skipped: offline, or hidden by flag.
	StateNotChecked State = "not_checked"
	// StateFailed means the lookup ran and errored.
	StateFailed State = "failed"
	// StateUnavailable means this build cannot look defences up at all yet.
	// Renderers print nothing for it unless explicitly asked.
	StateUnavailable State = "unavailable"
)

// Rule is one defence artefact. ArchiveURL is set only for Pro callers.
type Rule struct {
	UUID              string
	ArtifactID        string
	Kind              Kind
	Title             string
	Confidence        string // HIGH | MEDIUM | LOW
	DeployMode        string // the mode the rule says it is safe to start in, e.g. "log" or "block"
	FalsePositiveRisk string
	CoverageNotes     string
	MitreTechIDs      []string
	ExploitID         string
	ExploitSource     string
	ExploitURL        string
	// ArchiveURL is the relative path of the rule body, e.g.
	// /v2/virtual-patches/{uuid}/archive. Empty when the caller is not Pro.
	ArchiveURL string
	// ConsoleURL is the page for this rule in the Vulnetix console. The counts
	// endpoint returns it for Pro callers only.
	ConsoleURL string
	// SHA256 is the body checksum the archive endpoint also sends in
	// X-Vulnetix-Sha256, used to verify a download.
	SHA256 string
}

// LaneSummary is what is known about one lane for one vulnerability.
type LaneSummary struct {
	// Count is the total published, which every tier receives.
	Count int
	// ByKind is the per-format breakdown, which every tier receives.
	ByKind map[Kind]int
	// Rules carries the details, for Pro callers only.
	Rules []Rule
}

// Kinds returns the formats present in the lane, in a stable order.
func (l LaneSummary) Kinds() []Kind {
	out := make([]Kind, 0, len(l.ByKind))
	for k, n := range l.ByKind {
		if n > 0 {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return Name(out[i]) < Name(out[j]) })
	return out
}

// Summary is everything the CLI knows about the defences for one vulnerability.
type Summary struct {
	// ID is the identifier that was looked up.
	ID    string
	State State
	// Reason is a short explanation for the not-checked and failed states.
	Reason string
	Block  LaneSummary
	Detect LaneSummary
}

// Total is the number of defences across both lanes.
func (s Summary) Total() int { return s.Block.Count + s.Detect.Count }

// HasAny reports whether any defence is known to exist, whether or not its
// details were returned.
func (s Summary) HasAny() bool { return s.Total() > 0 }

// Rules returns every rule with details, block first, in a stable order.
func (s Summary) Rules() []Rule {
	out := append(append([]Rule{}, s.Block.Rules...), s.Detect.Rules...)
	return out
}

// Classify settles the state from the lane contents. A source calls this after
// filling the lanes so the rule is applied in one place.
func (s *Summary) Classify() {
	switch {
	case s.Total() == 0:
		s.State = StateNone
	case len(s.Block.Rules)+len(s.Detect.Rules) > 0:
		s.State = StateAvailable
	default:
		s.State = StateGated
	}
}

// ErrNotAvailable is returned by the stub source. It means "this build cannot
// fetch defences yet", which is different from an API failure.
var ErrNotAvailable = errors.New("defence lookup is not available in this build yet")

// LookupOptions describes the caller.
type LookupOptions struct {
	// Pro is true when the caller's plan includes rule bodies and downloads. The
	// server decides what a plan receives; this only decides whether to ask for
	// detail.
	Pro bool
	// Detail asks for the full records (coverage notes, checksum, the exploit each
	// rule came from). It costs a request per lane per advisory, so a scan leaves
	// it off and `defend` turns it on.
	Detail bool
}

// Body is a downloaded rule.
type Body struct {
	Kind     Kind
	FileName string
	Content  []byte
	// SHA256 is the checksum the server sent with the body.
	SHA256 string
}

// Source is the seam between the CLI and the vulnerability database.
type Source interface {
	// Lookup returns a Summary for each identifier it was able to look up.
	// Identifiers missing from the result were not looked up; Lookup does not
	// guess. It is called once per scan, with every no-fix identifier, so an
	// implementation is free to batch or to fan out under its own concurrency.
	Lookup(ctx context.Context, ids []string, opts LookupOptions) (map[string]Summary, error)

	// Download fetches one rule body. Pro only.
	Download(ctx context.Context, rule Rule) (Body, error)
}

// idPattern is the shape of an advisory identifier: a letter-led prefix, a hyphen,
// then the body (CVE-2024-1, GHSA-xxxx, PYSEC-2024-38, GO-2024-1, RUSTSEC-2024-1).
var idPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9._:-]+$`)

// Indexed reports whether id has the shape of an advisory identifier.
//
// The database looks up any advisory family and widens each id through its alias
// group, so a PYSEC or GO id finds defences filed under its CVE or GHSA. This used
// to allow only CVE, GHSA and CNVD, which under-reported; it now only refuses what
// is plainly not an identifier, and the server answers a malformed one per item.
func Indexed(id string) bool { return idPattern.MatchString(strings.TrimSpace(id)) }

// Resolve picks the identifier to look up for a finding: its own if indexed,
// otherwise the first indexed alias. It reports false when none is.
func Resolve(id string, aliases ...string) (string, bool) {
	if Indexed(id) {
		return strings.TrimSpace(id), true
	}
	for _, a := range aliases {
		if Indexed(a) {
			return strings.TrimSpace(a), true
		}
	}
	return "", false
}
