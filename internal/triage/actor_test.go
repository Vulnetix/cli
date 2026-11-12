package triage

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/vulnetix/cli/v4/internal/testutils"
)

// A decision names the signed-in account when there is one; the git config
// email (or user@host) is only the fallback for an unauthenticated run.
func TestDecisionActorPrefersSignedInAccount(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	testutils.HermeticGit(t)
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "ada@example.com"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	vulnetixDir := filepath.Join(dir, ".vulnetix")

	prev := AccountActor
	t.Cleanup(func() { AccountActor = prev })

	cases := []struct {
		name    string
		account func() string
		want    string
	}{
		{"signed in", func() string { return "vulnetix:acct-1" }, "vulnetix:acct-1"},
		{"no account hook", nil, "ada@example.com"},
		{"not signed in", func() string { return "" }, "ada@example.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			AccountActor = c.account
			if got := decisionActor(vulnetixDir); got != c.want {
				t.Fatalf("decisionActor = %q, want %q", got, c.want)
			}
		})
	}
}

// The provider's default decision is made for whoever ran triage, so it
// carries the signed-in account too.
func TestDefaultDecisionUsesSignedInAccount(t *testing.T) {
	prev := AccountActor
	t.Cleanup(func() { AccountActor = prev })
	AccountActor = func() string { return "vulnetix:acct-1" }

	for _, status := range []string{"not_affected", "fixed"} {
		d := decisionFromFailure(&TriageFinding{CVEID: "CVE-2021-23337", Status: status, Justification: "component_not_present"})
		if d == nil {
			t.Fatalf("%s: no default decision", status)
		}
		if d.Actor != "vulnetix:acct-1" {
			t.Errorf("%s: Actor = %q, want the signed-in account", status, d.Actor)
		}
	}
}
