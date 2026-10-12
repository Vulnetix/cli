// Package gitopen opens a git repository the way every history-reading feature needs it opened.
//
// go-git's PlainOpen follows a worktree's `.git` file to its private gitdir
// (`<main>/.git/worktrees/<name>`) but not on to the common dir that holds the object store, so
// the repository opens cleanly and then fails to find every commit: "object not found". A
// worktree is the normal way to work on several branches at once, and where coding agents work,
// so a feature that cannot read history there is broken in practice, not in an edge case.
// `EnableDotGitCommonDir` is the fix, and it is easy to forget at the one call site that matters,
// which is why the options live in one place.
package gitopen

import "github.com/go-git/go-git/v5"

// Open opens the repository at path.
//
// With detectParents false, path must be the repository root (as git.PlainOpen requires). With it
// true, a path anywhere inside a working tree resolves to the repository that contains it.
func Open(path string, detectParents bool) (*git.Repository, error) {
	return git.PlainOpenWithOptions(path, &git.PlainOpenOptions{
		DetectDotGit:          detectParents,
		EnableDotGitCommonDir: true,
	})
}
