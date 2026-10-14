package sast

import (
	"bytes"
	"embed"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// rulePack makes a local git repository at registry/org/repo holding n rules.
func rulePack(t *testing.T, registry, org, repo string, n int) RuleRef {
	t.Helper()
	dir := filepath.Join(registry, org, repo)
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("pack\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		src := "package vulnetix.rules.r" + string(rune('a'+i)) + "\n"
		if err := os.WriteFile(filepath.Join(dir, "rules", "r"+string(rune('a'+i))+".rego"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	wt, err := r.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := wt.AddGlob("."); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Commit("rules", &git.CommitOptions{Author: &object.Signature{Name: "t", Email: "t@example.invalid", When: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	return RuleRef{Org: org, Repo: repo}
}

// External packs report in one line; an empty pack keeps its own line, because
// the custom-rules docs troubleshoot a layout mistake by "Imported 0 rules".
func TestImportedPacksReportInOneLine(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	registry := t.TempDir()
	refs := []RuleRef{
		rulePack(t, registry, "acme", "first", 2),
		rulePack(t, registry, "acme", "second", 3),
		rulePack(t, registry, "acme", "empty", 0),
	}
	var out bytes.Buffer
	modules, err := LoadAllModules(embed.FS{}, true, refs, registry, &out)
	if err != nil {
		t.Fatal(err)
	}
	if len(modules) != 5 {
		t.Errorf("loaded %d modules, want 5", len(modules))
	}
	got := out.String()
	for _, want := range []string{"Imported 5 rules from 2 packs (acme/first +1 more)", "Imported 0 rules from acme/empty"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if n := strings.Count(got, "Imported "); n != 2 {
		t.Errorf("%d Imported lines, want 2:\n%s", n, got)
	}

	out.Reset()
	if _, err := LoadAllModules(embed.FS{}, true, refs[:1], registry, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Imported 2 rules from acme/first\n") {
		t.Errorf("one pack should be named on its own:\n%s", out.String())
	}
}
