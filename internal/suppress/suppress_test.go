package suppress

import "testing"

func TestRepoFullName(t *testing.T) {
	cases := map[string]string{
		"git@github.com:vulnetix/cli.git":      "vulnetix/cli",
		"https://github.com/vulnetix/cli.git":  "vulnetix/cli",
		"https://gitlab.com/grp/sub/repo":      "sub/repo",
		"ssh://git@host.tld:22/owner/repo.git": "owner/repo",
		"":                                     "",
		"not-a-remote":                         "",
	}
	for in, want := range cases {
		if got := RepoFullName([]string{in}); got != want {
			t.Errorf("RepoFullName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatching(t *testing.T) {
	set := NewSet([]Rule{
		{RuleID: "vnx-315", Category: "sast", IsActive: true},
		{FindingID: "CVE-2021-44228", Category: "sca", IsActive: true},
		{FilePath: "src/app.go", IsActive: true},
		{RuleID: "vnx-expired", IsActive: true, ExpiresAt: 1},
		{RuleID: "vnx-inactive", IsActive: false},
	}, 1000)

	if !set.Suppresses(Finding{Category: "sast", RuleID: "vnx-315"}) {
		t.Error("expected rule-id match")
	}
	if set.Suppresses(Finding{Category: "sast", RuleID: "vnx-999"}) {
		t.Error("unexpected match on different rule id")
	}
	if !set.Suppresses(Finding{Category: "sca", FindingID: "CVE-2021-44228"}) {
		t.Error("expected finding-id match")
	}
	if !set.Suppresses(Finding{Category: "iac", FilePath: "repo/src/app.go"}) {
		t.Error("expected path suffix match")
	}
	if set.Suppresses(Finding{RuleID: "vnx-expired"}) {
		t.Error("expired rule must not match")
	}
	if set.Suppresses(Finding{RuleID: "vnx-inactive"}) {
		t.Error("inactive rule must not match")
	}
}

func TestValueAnchorMatching(t *testing.T) {
	set := NewSet([]Rule{
		{Category: "crypto", TargetValue: "SHA-1", IsActive: true},
		{Category: "ai", TargetValue: "gpt-4o", FilePath: "src/llm.py", IsActive: true},
	}, 1000)

	if !set.Suppresses(Finding{Category: "crypto", Value: "SHA-1"}) {
		t.Error("expected value match")
	}
	// The console renders the SPDX id in whatever case the catalog carries, and
	// a user retypes it; a case difference must not silently disable the rule.
	if !set.Suppresses(Finding{Category: "crypto", Value: "sha-1"}) {
		t.Error("expected case-insensitive value match")
	}
	if set.Suppresses(Finding{Category: "crypto", Value: "SHA-256"}) {
		t.Error("unexpected match on a different value")
	}
	// Category is part of the anchor: a crypto rule must not reach AI inventory.
	if set.Suppresses(Finding{Category: "ai", Value: "SHA-1"}) {
		t.Error("crypto rule must not match an AI component")
	}
	if !set.Suppresses(Finding{Category: "ai", Value: "gpt-4o", FilePath: "repo/src/llm.py"}) {
		t.Error("expected value+path match")
	}
	if set.Suppresses(Finding{Category: "ai", Value: "gpt-4o", FilePath: "src/other.py"}) {
		t.Error("value rule with a file anchor must not match another file")
	}
}

func TestLineRangeMatching(t *testing.T) {
	set := NewSet([]Rule{
		{Category: "crypto", TargetValue: "MD5", FilePath: "a.go", LineRange: "10-14", IsActive: true},
		{Category: "crypto", TargetValue: "RC4", FilePath: "b.go", LineRange: "7", IsActive: true},
		{Category: "crypto", TargetValue: "DES", FilePath: "c.go", LineRange: "nonsense", IsActive: true},
	}, 1000)

	if !set.Suppresses(Finding{Category: "crypto", Value: "MD5", FilePath: "a.go", Line: 12}) {
		t.Error("expected line inside the range to match")
	}
	if !set.Suppresses(Finding{Category: "crypto", Value: "MD5", FilePath: "a.go", Line: 10}) {
		t.Error("range bounds are inclusive")
	}
	if set.Suppresses(Finding{Category: "crypto", Value: "MD5", FilePath: "a.go", Line: 20}) {
		t.Error("line outside the range must not match")
	}
	if !set.Suppresses(Finding{Category: "crypto", Value: "RC4", FilePath: "b.go", Line: 7}) {
		t.Error("expected single-line spec to match")
	}
	if set.Suppresses(Finding{Category: "crypto", Value: "RC4", FilePath: "b.go", Line: 8}) {
		t.Error("single-line spec must not match another line")
	}
	// An unparseable range is non-binding rather than a rule that matches nothing:
	// a malformed spec should not silently disable an otherwise-valid rule.
	if !set.Suppresses(Finding{Category: "crypto", Value: "DES", FilePath: "c.go", Line: 3}) {
		t.Error("unparseable range must not disable the rule")
	}
}

// A caller that does not know the line (every scanner family today) must be
// unaffected by a rule that carries a line range — nosec rules do carry one.
func TestLineRangeIgnoredWhenLineUnknown(t *testing.T) {
	set := NewSet([]Rule{
		{RuleID: "vnx-315", Category: "sast", FilePath: "a.go", LineRange: "10-14", IsActive: true},
	}, 1000)

	if !set.Suppresses(Finding{Category: "sast", RuleID: "vnx-315", FilePath: "a.go"}) {
		t.Error("a rule with a line range must still match when the finding has no line")
	}
}

// A value-only rule is a real anchor, not the anchorless match-everything rule
// the matcher guards against.
func TestValueOnlyRuleIsAnAnchor(t *testing.T) {
	set := NewSet([]Rule{{Category: "ai", TargetValue: "claude-opus-4", IsActive: true}}, 1000)

	if !set.Suppresses(Finding{Category: "ai", Value: "claude-opus-4"}) {
		t.Error("value-only rule should match its value")
	}
	if set.Suppresses(Finding{Category: "ai", Value: "some-other-model"}) {
		t.Error("value-only rule must not match everything")
	}
}
