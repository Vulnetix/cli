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
