package suppressdrift

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func commitAll(t *testing.T, wt *git.Worktree, msg string) {
	t.Helper()
	if err := wt.AddGlob("."); err != nil {
		t.Fatalf("add: %v", err)
	}
	_, err := wt.Commit(msg, &git.CommitOptions{
		Author: &object.Signature{Name: "t", Email: "t@t", When: time.Now()},
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func setupRepo(t *testing.T) (string, *git.Worktree) {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	return dir, wt
}

const snippet = "danger := runUserControlledThing(input)"

func TestReconcile_LineShift(t *testing.T) {
	dir, wt := setupRepo(t)
	write(t, dir, "app.go", "package main\n\nfunc f() {\n\t"+snippet+"\n}\n")
	commitAll(t, wt, "init")

	// Insert 3 lines above the snippet → it shifts from line 4 to line 7.
	write(t, dir, "app.go", "package main\n\n// a\n// b\n// c\nfunc f() {\n\t"+snippet+"\n}\n")
	commitAll(t, wt, "shift")

	res, err := Reconcile(dir, []Anchor{{Key: "k", FilePath: "app.go", LineNumber: 4, Snippet: snippet}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	r := res[0]
	if r.Gone {
		t.Fatalf("snippet should still be present")
	}
	if r.FilePath != "app.go" || r.Line != 7 {
		t.Fatalf("want app.go:7, got %s:%d", r.FilePath, r.Line)
	}
	if !r.Moved {
		t.Fatalf("expected Moved=true (line 4 -> 7)")
	}
}

func TestReconcile_Rename(t *testing.T) {
	dir, wt := setupRepo(t)
	write(t, dir, "old/app.go", "package main\n\nfunc f() {\n\t"+snippet+"\n}\n")
	commitAll(t, wt, "init")

	// Move the file to a new path.
	if err := os.MkdirAll(filepath.Join(dir, "new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "old/app.go"), filepath.Join(dir, "new/app.go")); err != nil {
		t.Fatal(err)
	}
	commitAll(t, wt, "rename")

	res, err := Reconcile(dir, []Anchor{{Key: "k", FilePath: "old/app.go", LineNumber: 4, Snippet: snippet}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	r := res[0]
	if r.Gone {
		t.Fatalf("snippet should be found at the new path")
	}
	if r.FilePath != "new/app.go" {
		t.Fatalf("want new/app.go, got %s", r.FilePath)
	}
	if !r.Moved {
		t.Fatalf("expected Moved=true after rename")
	}
}

func TestReconcile_Gone(t *testing.T) {
	dir, wt := setupRepo(t)
	write(t, dir, "app.go", "package main\n\nfunc f() {\n\t"+snippet+"\n}\n")
	commitAll(t, wt, "init")

	// Remove the snippet entirely.
	write(t, dir, "app.go", "package main\n\nfunc f() {\n}\n")
	commitAll(t, wt, "remove")

	res, err := Reconcile(dir, []Anchor{{Key: "k", FilePath: "app.go", LineNumber: 4, Snippet: snippet}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !res[0].Gone {
		t.Fatalf("expected Gone=true after the snippet was deleted")
	}
}
