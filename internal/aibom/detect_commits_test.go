package aibom

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func commitFile(t *testing.T, wt *git.Worktree, dir, name, content, msg string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Add(name); err != nil {
		t.Fatal(err)
	}
	_, err := wt.Commit(msg, &git.CommitOptions{
		Author: &object.Signature{Name: "Dev", Email: "dev@example.com", When: time.Unix(1700000000, 0)},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDetectCommitsAttributesAgents(t *testing.T) {
	cc := compiledCatalog(t)
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}

	// A commit whose trailer attributes Claude Code, and an unrelated human commit.
	commitFile(t, wt, dir, "a.txt", "one", "chore: ordinary human commit")
	commitFile(t, wt, dir, "b.txt", "two",
		"feat: add feature\n\nCo-Authored-By: Claude <noreply@anthropic.com>\nClaude-Session: https://claude.ai/code/session_01ABC")

	det, err := Detect(Options{Root: dir, Catalog: cc, ScanCommits: true})
	if err != nil {
		t.Fatal(err)
	}

	if !toolIDs(det)["claude-code"] {
		t.Fatal("claude-code not detected from commit trailer")
	}
	var sawCommitEvidence bool
	for _, tl := range det.Tools {
		if tl.ID != "claude-code" {
			continue
		}
		if tl.Confidence != "high" {
			t.Errorf("claude-code commit confidence = %q, want high", tl.Confidence)
		}
		for _, e := range tl.Evidence {
			if e.Method == "commit" {
				sawCommitEvidence = true
			}
		}
	}
	if !sawCommitEvidence {
		t.Error("expected commit-method evidence on claude-code")
	}
}

func TestDetectCommitsDisabledAndNoMatch(t *testing.T) {
	cc := compiledCatalog(t)
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	// AI trailer present, but the commit pass is disabled -> not detected here.
	commitFile(t, wt, dir, "b.txt", "two",
		"feat: x\n\nCo-Authored-By: Claude <noreply@anthropic.com>")
	det, err := Detect(Options{Root: dir, Catalog: cc, ScanCommits: false})
	if err != nil {
		t.Fatal(err)
	}
	if toolIDs(det)["claude-code"] {
		t.Error("claude-code should not be detected when ScanCommits is false")
	}

	// A plain human-only repo must not attribute any tool via commits.
	dir2 := t.TempDir()
	repo2, _ := git.PlainInit(dir2, false)
	wt2, _ := repo2.Worktree()
	commitFile(t, wt2, dir2, "c.txt", "x", "fix: a normal bug fix with no agent involved")
	det2, err := Detect(Options{Root: dir2, Catalog: cc, ScanCommits: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(det2.Tools) != 0 {
		t.Errorf("plain repo attributed tools via commits: %d", len(det2.Tools))
	}
}
