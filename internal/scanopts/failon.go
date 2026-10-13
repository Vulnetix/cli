package scanopts

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/vulnetix/cli/v3/internal/pipeline"
	"github.com/vulnetix/cli/v3/internal/scan"
)

// FailOnRules are the values `--fail-on` accepts, for help and completion.
var FailOnRules = []string{
	"low", "medium", "high", "critical",
	"kev", "exploit=poc", "exploit=active", "exploit=weaponized",
	"malware", "eol", "unpinned", "unprotected", "lag=", "cooldown=",
}

// FailOn is a parsed `--fail-on` value.
//
// It is a vocabulary over the gates that already exist, not a second set of
// gates: ApplyTo folds it into the same pipeline.Options fields the legacy
// flags populate, so there is one evaluation path and one place an org quality
// gate can override. Seven flags that each meant "exit 1 when" become one.
type FailOn struct {
	Severity    string
	Exploits    string
	Malware     bool
	EOL         bool
	EOLSeverity string
	Unpinned    bool
	Unprotected bool
	Lag         int
	CooldownDay int
}

// ParseFailOn parses repeatable, comma-separated `--fail-on` values. The first
// unrecognised rule is an error that lists every valid one.
func ParseFailOn(values []string) (FailOn, error) {
	var f FailOn
	for _, v := range values {
		for _, raw := range strings.Split(v, ",") {
			rule := strings.ToLower(strings.TrimSpace(raw))
			if rule == "" {
				continue
			}
			name, arg, hasArg := strings.Cut(rule, "=")
			switch {
			case isSeverity(rule):
				f.Severity = stricterSeverity(f.Severity, rule)
			case name == "kev":
				f.Exploits = strongerExploit(f.Exploits, "active")
			case name == "exploit" && hasArg:
				e, err := NormaliseExploits(arg)
				if err != nil || e == "" {
					return f, badRule(raw)
				}
				f.Exploits = strongerExploit(f.Exploits, e)
			case name == "malware" && !hasArg:
				f.Malware = true
			case name == "eol":
				f.EOL = true
				if hasArg {
					if !isSeverity(arg) {
						return f, badRule(raw)
					}
					f.EOLSeverity = arg
				}
			case name == "unpinned" && !hasArg:
				f.Unpinned = true
			case name == "unprotected" && !hasArg:
				f.Unprotected = true
			case name == "lag" && hasArg:
				n, err := strconv.Atoi(arg)
				if err != nil || n < 1 {
					return f, badRule(raw)
				}
				f.Lag = n
			case name == "cooldown" && hasArg:
				n, err := strconv.Atoi(strings.TrimSuffix(arg, "d"))
				if err != nil || n < 1 {
					return f, badRule(raw)
				}
				f.CooldownDay = n
			default:
				return f, badRule(raw)
			}
		}
	}
	return f, nil
}

func badRule(raw string) error {
	return fmt.Errorf("--fail-on: unknown rule %q (valid: low, medium, high, critical, kev, exploit=poc|active|weaponized, malware, eol[=severity], unpinned, unprotected, lag=<n>, cooldown=<n>d)", strings.TrimSpace(raw))
}

func isSeverity(s string) bool {
	for _, v := range scan.ValidSeverityThresholds {
		if s == v {
			return true
		}
	}
	return false
}

// stricterSeverity returns the lower threshold: failing on "low" is stricter
// than failing on "high".
func stricterSeverity(a, b string) string {
	if a == "" {
		return b
	}
	rank := func(s string) int {
		for i, v := range scan.ValidSeverityThresholds {
			if s == v {
				return i
			}
		}
		return len(scan.ValidSeverityThresholds)
	}
	if rank(b) < rank(a) {
		return b
	}
	return a
}

// strongerExploit returns the more permissive tier, because poc catches
// everything active and weaponized do.
func strongerExploit(a, b string) string {
	if a == "" {
		return b
	}
	rank := func(s string) int {
		for i, v := range scan.ValidExploitThresholds {
			if s == v {
				return i
			}
		}
		return len(scan.ValidExploitThresholds)
	}
	if rank(b) < rank(a) {
		return b
	}
	return a
}

// ApplyTo folds the rules into opts. Where a legacy flag already set the same
// gate the stricter of the two wins, so mixing vocabularies never loosens a
// pipeline.
func (f FailOn) ApplyTo(opts *pipeline.Options) {
	opts.SeverityThreshold = stricterSeverity(opts.SeverityThreshold, f.Severity)
	if f.Exploits != "" {
		opts.ExploitThreshold = strongerExploit(opts.ExploitThreshold, f.Exploits)
	}
	opts.BlockMalware = opts.BlockMalware || f.Malware
	opts.BlockEOL = opts.BlockEOL || f.EOL
	opts.BlockUnpinned = opts.BlockUnpinned || f.Unpinned
	opts.FailOnUnprotected = opts.FailOnUnprotected || f.Unprotected
	if f.Lag > 0 && (opts.VersionLag == 0 || f.Lag > opts.VersionLag) {
		opts.VersionLag = f.Lag
	}
	if f.CooldownDay > opts.CooldownDays {
		opts.CooldownDays = f.CooldownDay
	}
}
