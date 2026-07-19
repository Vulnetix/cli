// Package suppress holds the shared "ignore rule" matching logic used by every
// scanner pipeline (SAST family, SCA, license, malscan) to drop findings that
// an org-level or local Suppression covers, before report output is generated.
//
// A rule is anchored by one or more of: rego rule id (the rego file id), a
// finding id (CVE/vuln id), or a file path. A finding is suppressed when every
// anchor the rule specifies matches the finding and the rule is active and
// unexpired.
package suppress

import (
	"strings"

	"github.com/vulnetix/cli/v3/internal/memory"
)

// Rule is the normalized form a Set matches against. It is produced from a
// memory.SuppressionRecord (local) or a backend Suppression (remote).
type Rule struct {
	UUID               string
	RuleID             string
	Category           string
	Type               string
	Reason             string
	FindingID          string
	FilePath           string
	LineRange          string
	RepositoryFullName string
	Branch             string
	ExpiresAt          int64
	IsActive           bool
}

// Finding is the subset of any scanner result the matcher inspects.
type Finding struct {
	Category  string
	RuleID    string
	FindingID string
	FilePath  string
}

// Set is a matchable collection of rules.
type Set struct {
	rules []Rule
	now   int64
}

// NewSet builds a Set from rules, keeping only those active and unexpired at now.
func NewSet(rules []Rule, now int64) *Set {
	kept := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if !r.IsActive {
			continue
		}
		if r.ExpiresAt > 0 && r.ExpiresAt <= now {
			continue
		}
		kept = append(kept, r)
	}
	return &Set{rules: kept, now: now}
}

// Empty reports whether the set has no active rules.
func (s *Set) Empty() bool { return s == nil || len(s.rules) == 0 }

// Match returns the first rule that suppresses f, and whether one was found.
func (s *Set) Match(f Finding) (Rule, bool) {
	if s == nil {
		return Rule{}, false
	}
	for _, r := range s.rules {
		if ruleMatches(r, f) {
			return r, true
		}
	}
	return Rule{}, false
}

// Suppresses is Match without the matched rule.
func (s *Set) Suppresses(f Finding) bool {
	_, ok := s.Match(f)
	return ok
}

func ruleMatches(r Rule, f Finding) bool {
	if r.Category != "" && !strings.EqualFold(r.Category, f.Category) {
		return false
	}
	if r.RuleID != "" && !strings.EqualFold(r.RuleID, f.RuleID) {
		return false
	}
	if r.FindingID != "" && !strings.EqualFold(r.FindingID, f.FindingID) {
		return false
	}
	if r.FilePath != "" && !pathMatches(r.FilePath, f.FilePath) {
		return false
	}
	// A rule with no anchor at all would match everything; guard against it.
	return r.RuleID != "" || r.FindingID != "" || r.FilePath != ""
}

// pathMatches compares two file paths tolerant of leading "./" and separator
// direction; a rule path matches when it equals or is a suffix of the finding
// path (so "src/app.go" covers "repo/src/app.go").
func pathMatches(rulePath, findingPath string) bool {
	rp := normPath(rulePath)
	fp := normPath(findingPath)
	if rp == "" || fp == "" {
		return false
	}
	return rp == fp || strings.HasSuffix(fp, "/"+rp)
}

func normPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "./")
	return strings.Trim(p, "/")
}

// FromMemory converts local suppression records to matcher rules.
func FromMemory(recs []memory.SuppressionRecord) []Rule {
	out := make([]Rule, 0, len(recs))
	for _, s := range recs {
		out = append(out, Rule{
			UUID:               s.UUID,
			RuleID:             s.RuleID,
			Category:           s.Category,
			Type:               s.Type,
			Reason:             s.Reason,
			FindingID:          s.FindingID,
			FilePath:           s.FilePath,
			LineRange:          s.LineRange,
			RepositoryFullName: s.RepositoryFullName,
			Branch:             s.Branch,
			ExpiresAt:          s.ExpiresAt,
			IsActive:           s.IsActive,
		})
	}
	return out
}

// RepoFullName derives "owner/repo" from the first parseable git remote URL.
// Supports scp-style (git@github.com:owner/repo.git) and URL-style
// (https://host/owner/repo.git) remotes. Returns "" when none parse.
func RepoFullName(remotes []string) string {
	for _, raw := range remotes {
		if fn := parseRemote(raw); fn != "" {
			return fn
		}
	}
	return ""
}

func parseRemote(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Strip scheme / user@host, keep the path portion.
	path := raw
	if i := strings.Index(raw, "://"); i >= 0 {
		rest := raw[i+3:]
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			path = rest[slash+1:]
		}
	} else if at := strings.LastIndex(raw, "@"); at >= 0 {
		rest := raw[at+1:] // host:owner/repo.git
		if colon := strings.IndexByte(rest, ':'); colon >= 0 {
			path = rest[colon+1:]
		}
	} else if colon := strings.IndexByte(raw, ':'); colon >= 0 {
		path = raw[colon+1:]
	}
	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return ""
	}
	owner := parts[len(parts)-2]
	repo := parts[len(parts)-1]
	if owner == "" || repo == "" {
		return ""
	}
	return owner + "/" + repo
}
