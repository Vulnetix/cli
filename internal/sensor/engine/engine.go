// Package engine compiles a feed's rules into what the sensor can run, and
// reports, per rule, whether it compiled. That report is the whole basis for
// the console calling a rule "protecting": a rule this package could not
// compile, or has no engine for, is never shown as running.
//
// Engines:
//
//   - MODSECURITY and the generated virtual patches in that format run on
//     Coraza, in detection-only mode: Coraza says which rule matched and the
//     verdict engine decides what to do about it.
//   - REGEX_L7 runs on Go's RE2. A pattern that needs PCRE (lookaround,
//     backreferences) is rejected with that reason rather than approximated.
//   - STIX and OpenIOC become sets of domains, IP addresses and file hashes
//     for the egress proxy, the DNS check and the file scan.
//
// Snort, Suricata, YARA, Sigma, AWS WAF, Cloudflare and nginx rules are loaded
// as no-engine: this sensor build cannot run them, and says so.
package engine

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/feed"
)

// Load statuses, as the runtime API names them.
const (
	Compiled = "compiled"
	Rejected = "rejected"
	NoEngine = "no-engine"
)

// Result is one rule's load outcome.
type Result struct {
	Rule   feed.Rule
	Status string
	Reason string
}

// Hit is one rule matching one request.
type Hit struct {
	Rule   decide.RuleRef
	Detail string
}

// Set is everything compiled from one or more feeds.
type Set struct {
	modsec *modsecEngine
	regex  []regexRule
	IOC    IOCSet
}

type regexRule struct {
	ref decide.RuleRef
	re  *regexp.Regexp
}

// Compile builds a Set from rules and returns each rule's outcome. A disabled
// rule is reported as rejected ("disabled in the feed") and never runs.
func Compile(rules []feed.Rule) (*Set, []Result) {
	set := &Set{IOC: newIOCSet()}
	results := make([]Result, 0, len(rules))
	var modsec []feed.Rule

	for _, r := range rules {
		if r.Disabled {
			results = append(results, Result{Rule: r, Status: Rejected, Reason: "disabled in the feed"})

			continue
		}
		switch strings.ToUpper(r.RuleType) {
		case "MODSECURITY":
			modsec = append(modsec, r)
		case "REGEX_L7":
			re, reason := compileRegexL7(r.Body)
			if re == nil {
				results = append(results, Result{Rule: r, Status: Rejected, Reason: reason})

				continue
			}
			set.regex = append(set.regex, regexRule{ref: ref(r), re: re})
			results = append(results, Result{Rule: r, Status: Compiled})
		case "STIX", "OPENIOC":
			n, err := set.IOC.add(ref(r), r.RuleType, r.Body)
			switch {
			case err != nil:
				results = append(results, Result{Rule: r, Status: Rejected, Reason: err.Error()})
			case n == 0:
				results = append(results, Result{Rule: r, Status: Rejected, Reason: "no domain, IP or file hash indicators the sensor can match"})
			default:
				results = append(results, Result{Rule: r, Status: Compiled})
			}
		default:
			results = append(results, Result{Rule: r, Status: NoEngine, Reason: fmt.Sprintf("this sensor has no %s engine", r.RuleType)})
		}
	}

	engine, modsecResults := compileModSecurity(modsec)
	set.modsec = engine

	return set, append(results, modsecResults...)
}

// InspectRequest runs the HTTP engines over one request. body is what was
// buffered of it, possibly cut short.
func (s *Set) InspectRequest(r *http.Request, body []byte) []Hit {
	var hits []Hit
	if s.modsec != nil {
		hits = append(hits, s.modsec.inspect(r, body)...)
	}
	if len(s.regex) > 0 {
		line := r.Method + " " + r.URL.RequestURI()
		for _, rr := range s.regex {
			if rr.re.MatchString(line) {
				hits = append(hits, Hit{Rule: rr.ref, Detail: "request line matched"})

				continue
			}
			for name, values := range r.Header {
				if matchesAny(rr.re, name, values) {
					hits = append(hits, Hit{Rule: rr.ref, Detail: "header " + name + " matched"})

					break
				}
			}
		}
	}

	return dedupe(hits)
}

func matchesAny(re *regexp.Regexp, name string, values []string) bool {
	for _, v := range values {
		if re.MatchString(name + ": " + v) {
			return true
		}
	}

	return false
}

func dedupe(hits []Hit) []Hit {
	seen := map[decide.RuleRef]bool{}
	out := hits[:0]
	for _, h := range hits {
		if seen[h.Rule] {
			continue
		}
		seen[h.Rule] = true
		out = append(out, h)
	}

	return out
}

func ref(r feed.Rule) decide.RuleRef {
	return decide.RuleRef{Table: r.RuleTable, UUID: r.RuleUUID}
}

// compileRegexL7 reads a Layer 7 regex rule: the pattern on its first
// non-comment line. Go's RE2 has no lookaround or backreferences; such a
// pattern is rejected by name rather than silently matched differently.
func compileRegexL7(body string) (*regexp.Regexp, string) {
	var pattern string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pattern = line

		break
	}
	if pattern == "" {
		return nil, "empty pattern"
	}
	if strings.HasPrefix(pattern, "/") && strings.LastIndex(pattern, "/") > 0 {
		end := strings.LastIndex(pattern, "/")
		flags := pattern[end+1:]
		pattern = pattern[1:end]
		if strings.Contains(flags, "i") {
			pattern = "(?i)" + pattern
		}
	}
	for _, pcre := range []string{"(?=", "(?!", "(?<=", "(?<!", `\1`, `\2`} {
		if strings.Contains(pattern, pcre) {
			return nil, "uses " + pcre + ", which RE2 does not support"
		}
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, "does not compile: " + err.Error()
	}

	return re, ""
}
