package gitctx

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// initRepo creates a fresh repository with PlainInit (never the git binary: in
// this sandbox `git init` dies on the harness's read-only config lock) and
// sets a local user identity so commits and annotated tags are well-formed.
func initRepo(t *testing.T) *git.Repository {
	t.Helper()
	repo, err := git.PlainInit(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := repo.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.User.Name = "Test User"
	cfg.User.Email = "test@example.com"
	if err := repo.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	return repo
}

// commit creates one commit on the repository's current branch with a fixed
// author, and returns the new HEAD commit.
func commit(t *testing.T, repo *git.Repository, author object.Signature, msg string) *object.Commit {
	t.Helper()
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt.Filesystem.Root(), "f.txt"), []byte(msg+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Add("f.txt"); err != nil {
		t.Fatal(err)
	}
	hash, err := wt.Commit(msg, &git.CommitOptions{Author: &author})
	if err != nil {
		t.Fatal(err)
	}
	c, err := repo.CommitObject(hash)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// repoRoot returns the worktree root of repo, matching what Collect stores in RepoRootPath.
func repoRoot(t *testing.T, repo *git.Repository) string {
	t.Helper()
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	return wt.Filesystem.Root()
}

func TestCollectBasic(t *testing.T) {
	repo := initRepo(t)
	root := repoRoot(t, repo)

	// Rule 1: nil remotes produce an empty RemoteURLs slice, not nil.
	got := Collect(root)
	if got == nil {
		t.Fatal("Collect returned nil for a valid repository")
	}
	if got.RemoteURLs == nil {
		t.Error("RemoteURLs is nil with no remotes, want an empty slice")
	}
	if len(got.RemoteURLs) != 0 {
		t.Errorf("RemoteURLs = %v, want empty", got.RemoteURLs)
	}

	// Rule 1: one remote with two URLs lists both.
	if _, err := repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{"https://example.com/a.git", "git@example.com:a.git"},
	}); err != nil {
		t.Fatal(err)
	}
	got = Collect(root)
	if len(got.RemoteURLs) != 2 {
		t.Fatalf("RemoteURLs = %v, want both URLs of one remote", got.RemoteURLs)
	}
	sort.Strings(got.RemoteURLs)
	if got.RemoteURLs[0] != "git@example.com:a.git" || got.RemoteURLs[1] != "https://example.com/a.git" {
		t.Errorf("RemoteURLs = %v", got.RemoteURLs)
	}

	// Rule 1: HEAD on a branch, commit details, message truncated to first line.
	when := time.Date(2026, 11, 5, 10, 30, 0, 0, time.FixedZone("+02:00", 2*3600))
	author := object.Signature{Name: "Ada Lovelace", Email: "ada@example.com", When: when}
	first := commit(t, repo, author, "first commit\n\nbody paragraph")
	got = Collect(root)
	if got.CurrentBranch != "master" {
		t.Errorf("CurrentBranch = %q, want master", got.CurrentBranch)
	}
	if got.CurrentCommit != first.Hash.String() {
		t.Errorf("CurrentCommit = %q, want %q", got.CurrentCommit, first.Hash.String())
	}
	if got.HeadCommitMessage != "first commit" {
		t.Errorf("HeadCommitMessage = %q, want first line only", got.HeadCommitMessage)
	}
	if got.HeadCommitAuthor != "Ada Lovelace" || got.HeadCommitEmail != "ada@example.com" {
		t.Errorf("author = %q <%q>, want Ada Lovelace <ada@example.com>", got.HeadCommitAuthor, got.HeadCommitEmail)
	}
	// The stored timestamp is the author time converted to UTC and RFC3339.
	if got.HeadCommitTimestamp != "2026-11-05T08:30:00Z" {
		t.Errorf("HeadCommitTimestamp = %q, want 2026-11-05T08:30:00Z", got.HeadCommitTimestamp)
	}
}

func TestCollectDetachedHead(t *testing.T) {
	repo := initRepo(t)
	root := repoRoot(t, repo)
	when := time.Now()
	head := commit(t, repo, object.Signature{Name: "Ada", Email: "ada@example.com", When: when}, "first")

	// Rule 1: a detached HEAD reads as "HEAD (detached)" and still carries the commit.
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := wt.Checkout(&git.CheckoutOptions{Hash: head.Hash}); err != nil {
		t.Fatal(err)
	}
	got := Collect(root)
	if got.CurrentBranch != "HEAD (detached)" {
		t.Errorf("CurrentBranch = %q, want HEAD (detached)", got.CurrentBranch)
	}
	if got.CurrentCommit != head.Hash.String() {
		t.Errorf("CurrentCommit = %q, want %q", got.CurrentCommit, head.Hash.String())
	}
}

func TestCollectTagsAtHead(t *testing.T) {
	repo := initRepo(t)
	root := repoRoot(t, repo)
	when := time.Now()
	head := commit(t, repo, object.Signature{Name: "Ada", Email: "ada@example.com", When: when}, "first")
	hash := head.Hash

	// Rule 2: a lightweight tag at HEAD is listed.
	if _, err := repo.CreateTag("v1.0.0", hash, nil); err != nil {
		t.Fatal(err)
	}
	// Rule 2: an annotated tag object targeting HEAD is listed.
	if _, err := repo.CreateTag("v2.0.0", hash, &git.CreateTagOptions{
		Tagger:  &object.Signature{Name: "Ada", Email: "ada@example.com", When: when},
		Message: "release v2\n",
	}); err != nil {
		t.Fatal(err)
	}
	// Rule 2: a tag elsewhere is not listed. Tag the next commit, then move
	// HEAD past it, so the tag never points at the final HEAD.
	other := commit(t, repo, object.Signature{Name: "Ada", Email: "ada@example.com", When: when.Add(time.Minute)}, "second")
	if _, err := repo.CreateTag("v0.1.0", other.Hash, nil); err != nil {
		t.Fatal(err)
	}
	commit(t, repo, object.Signature{Name: "Ada", Email: "ada@example.com", When: when.Add(2 * time.Minute)}, "third")

	got := Collect(root)
	if len(got.HeadTags) != 0 {
		t.Errorf("HeadTags = %v, want none (tags point at earlier commits)", got.HeadTags)
	}

	// Move HEAD back to the tagged commit: both tags at HEAD are listed.
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := wt.Checkout(&git.CheckoutOptions{Hash: hash}); err != nil {
		t.Fatal(err)
	}
	got = Collect(root)
	sort.Strings(got.HeadTags)
	if len(got.HeadTags) != 2 || got.HeadTags[0] != "v1.0.0" || got.HeadTags[1] != "v2.0.0" {
		t.Errorf("HeadTags = %v, want [v1.0.0 v2.0.0]", got.HeadTags)
	}
}

func TestCollectRecentCommitters(t *testing.T) {
	repo := initRepo(t)
	root := repoRoot(t, repo)

	// Rule 3: two commits by one email collapse into one entry with Count 2.
	alice := object.Signature{Name: "Alice A", Email: "alice@example.com", When: time.Now()}
	commit(t, repo, alice, "one")
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "f.txt"), []byte("two\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Add("f.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Commit("two", &git.CommitOptions{Author: &alice}); err != nil {
		t.Fatal(err)
	}
	got := Collect(root)
	if len(got.RecentCommitters) != 1 {
		t.Fatalf("RecentCommitters = %v, want one entry", got.RecentCommitters)
	}
	if got.RecentCommitters[0].Email != "alice@example.com" || got.RecentCommitters[0].Count != 2 {
		t.Errorf("RecentCommitters[0] = %+v, want alice@example.com with Count 2", got.RecentCommitters[0])
	}

	// Rule 3: 49 more commits from two alternating authors make 51 total; the
	// log is capped at maxLogCommits (50), so the oldest commit drops out and
	// the tally sums to 50.
	for i := 0; i < 49; i++ {
		name, email := "Alice A", "alice@example.com"
		if i%2 == 1 {
			name, email = "Bob B", "bob@example.com"
		}
		author := object.Signature{Name: name, Email: email, When: time.Now().Add(time.Duration(i) * time.Second)}
		if err := os.WriteFile(filepath.Join(root, "f.txt"), []byte(fmt.Sprintf("loop %d\n", i)), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := wt.Add("f.txt"); err != nil {
			t.Fatal(err)
		}
		if _, err := wt.Commit(fmt.Sprintf("commit %d", i), &git.CommitOptions{Author: &author}); err != nil {
			t.Fatal(err)
		}
	}
	got = Collect(root)
	total := 0
	for _, ci := range got.RecentCommitters {
		total += ci.Count
	}
	if total != maxLogCommits {
		t.Errorf("committer counts sum to %d, want %d (log capped)", total, maxLogCommits)
	}
	if len(got.RecentCommitters) != 2 {
		t.Errorf("RecentCommitters = %v, want both authors", got.RecentCommitters)
	}
	// Rule 3: ordering is descending by Count.
	if got.RecentCommitters[0].Count < got.RecentCommitters[1].Count {
		t.Errorf("RecentCommitters not sorted by Count descending: %v", got.RecentCommitters)
	}
}

func TestCollectIsWorktree(t *testing.T) {
	// Rule 4: a normal repository has .git as a directory, so IsWorktree is false.
	repo := initRepo(t)
	root := repoRoot(t, repo)
	got := Collect(root)
	if got.IsWorktree {
		t.Error("IsWorktree = true for a normal repo, want false")
	}

	// Rule 4: a linked worktree has .git as a file pointing at the main git
	// dir. Build it with PlainInit plus a hand-written .git file, as git
	// worktree add does, without invoking the git binary.
	dirA := t.TempDir()
	main, err := git.PlainInit(dirA, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := main.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.User.Name = "Test User"
	cfg.User.Email = "test@example.com"
	if err := main.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	wt, err := main.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	when := time.Now()
	if err := os.WriteFile(filepath.Join(dirA, "f.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Add("f.txt"); err != nil {
		t.Fatal(err)
	}
	first, err := wt.Commit("first", &git.CommitOptions{Author: &object.Signature{Name: "Ada", Email: "ada@example.com", When: when}})
	if err != nil {
		t.Fatal(err)
	}

	dirB := filepath.Join(t.TempDir(), "linked")
	if err := os.MkdirAll(dirB, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirB, ".git"), []byte("gitdir: "+dirA+"/.git\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	linked := Collect(dirB)
	if linked == nil {
		t.Fatal("Collect returned nil for the linked worktree")
	}
	if !linked.IsWorktree {
		t.Error("IsWorktree = false for a .git-file worktree, want true")
	}
	// The linked worktree still reads HEAD and the commit from the main gitdir.
	if linked.CurrentCommit != first.String() {
		t.Errorf("CurrentCommit = %q, want %q", linked.CurrentCommit, first.String())
	}
}
