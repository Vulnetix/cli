package analyze

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

// A shallow checkout is what CI hands us: `actions/checkout` clones at depth 1 unless
// asked otherwise, so the boundary commits are present and their parents are not. This
// fixture reproduces that on disk — a real `.git/shallow` file plus the missing parent
// object — because the failure it caused was not theoretical: every `vulnetix analyze`
// run in CI aborted its history walk with "object not found", and every contributor,
// commit and activity metric was absent from every report as a result.
func newShallowRepo(t *testing.T, depth int) (*git.Repository, string) {
	t.Helper()

	root := t.TempDir()
	repo, err := git.PlainInit(root, false)
	require.NoError(t, err)
	wt, err := repo.Worktree()
	require.NoError(t, err)

	authors := []object.Signature{
		{Name: "Ada Lovelace", Email: "ada@example.com"},
		{Name: "Grace Hopper", Email: "grace@example.com"},
		{Name: "Alan Turing", Email: "alan@example.com"},
	}
	base := time.Now().Add(-72 * time.Hour)

	hashes := make([]plumbing.Hash, 0, len(authors))
	for i, who := range authors {
		name := filepath.Join(root, "file.txt")
		require.NoError(t, os.WriteFile(name, []byte(who.Email+"\n"), 0o600))
		_, err = wt.Add("file.txt")
		require.NoError(t, err)

		who.When = base.Add(time.Duration(i) * time.Hour)
		h, cerr := wt.Commit("commit "+who.Email, &git.CommitOptions{Author: &who, Committer: &who})
		require.NoError(t, cerr)
		hashes = append(hashes, h)
	}

	// Graft the history exactly as a `--depth N` fetch does: the newest `depth` commits
	// stay, the boundary commit is listed in .git/shallow, and everything older is gone.
	boundary := hashes[len(hashes)-depth]
	require.NoError(t, repo.Storer.SetShallow([]plumbing.Hash{boundary}))
	for _, h := range hashes[:len(hashes)-depth] {
		s := h.String()
		require.NoError(t, os.Remove(filepath.Join(root, ".git", "objects", s[:2], s[2:])))
	}

	reopened, err := git.PlainOpen(root)
	require.NoError(t, err)

	return reopened, root
}

// The walk must end at the graft and keep everything it read, rather than failing the
// whole collector and discarding it.
func TestCollectGitWalksShallowClone(t *testing.T) {
	repo, root := newShallowRepo(t, 2)

	b := NewBuilder(Tool{Name: "test", Version: "dev"}, Target{RepoID: "acme/demo", RootPath: root}, time.Now())
	opts := DefaultOptions()
	opts.Path = root

	st, err := collectGit(b, repo, opts, time.Now(), reporter{})
	require.NoError(t, err)
	require.Len(t, st.commits, 2, "both commits inside the graft must be read")
	require.Len(t, st.contributors, 2)
	require.True(t, st.truncated, "a grafted history is truncated history and must say so")
	require.Contains(t, st.truncationReason, "shallow")
}

// Depth 1 is the CI default and the case that produced the empty contributor directory.
func TestCollectGitWalksDepthOneClone(t *testing.T) {
	repo, root := newShallowRepo(t, 1)

	b := NewBuilder(Tool{Name: "test", Version: "dev"}, Target{RepoID: "acme/demo", RootPath: root}, time.Now())
	opts := DefaultOptions()
	opts.Path = root

	st, err := collectGit(b, repo, opts, time.Now(), reporter{})
	require.NoError(t, err)
	require.Len(t, st.commits, 1)
	require.Len(t, st.contributors, 1)
	require.Equal(t, "alan@example.com", st.contributors[0].Identity.Email)
	require.True(t, st.truncated)
}

// A complete clone must stay complete: no truncation claim, every commit read.
func TestCollectGitWalksCompleteClone(t *testing.T) {
	root := t.TempDir()
	repo, err := git.PlainInit(root, false)
	require.NoError(t, err)
	wt, err := repo.Worktree()
	require.NoError(t, err)
	base := time.Now().Add(-48 * time.Hour)
	for i, who := range []object.Signature{
		{Name: "Ada Lovelace", Email: "ada@example.com"},
		{Name: "Grace Hopper", Email: "grace@example.com"},
	} {
		require.NoError(t, os.WriteFile(filepath.Join(root, "file.txt"), []byte(who.Email+"\n"), 0o600))
		_, err = wt.Add("file.txt")
		require.NoError(t, err)
		who.When = base.Add(time.Duration(i) * time.Hour)
		_, err = wt.Commit("commit "+who.Email, &git.CommitOptions{Author: &who, Committer: &who})
		require.NoError(t, err)
	}

	b := NewBuilder(Tool{Name: "test", Version: "dev"}, Target{RepoID: "acme/demo", RootPath: root}, time.Now())
	opts := DefaultOptions()
	opts.Path = root

	st, err := collectGit(b, repo, opts, time.Now(), reporter{})
	require.NoError(t, err)
	require.Len(t, st.commits, 2)
	require.False(t, st.truncated)
	require.Empty(t, st.truncationReason)

	// The branch the commits were made on is a record, not just a run-level string.
	require.Len(t, st.branches, 1)
	require.NotEmpty(t, st.branches[0].Name)
	require.NotEmpty(t, st.branches[0].LastCommitAt)
	require.NotNil(t, st.branches[0].AgeSeconds)
}

// A branch whose tip this checkout does not hold is not a branch we can describe, and must
// not become a record with invented dates.
func TestCollectBranchesSkipsRefsWithNoObject(t *testing.T) {
	repo, root := newShallowRepo(t, 1)
	require.NoError(t, repo.Storer.SetReference(
		plumbing.NewHashReference("refs/heads/ghost", plumbing.NewHash("0123456789012345678901234567890123456789"))))

	b := NewBuilder(Tool{Name: "test", Version: "dev"}, Target{RepoID: "acme/demo", RootPath: root}, time.Now())
	opts := DefaultOptions()
	opts.Path = root

	st, err := collectGit(b, repo, opts, time.Now(), reporter{})
	require.NoError(t, err)
	for _, br := range st.branches {
		require.NotEqual(t, "ghost", br.Name)
	}
}
