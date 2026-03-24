package gitctx

import (
	"sort"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// GitContext holds repository metadata collected via go-git.
type GitContext struct {
	RemoteURLs       []string        `json:"remoteUrls"`
	CurrentBranch    string          `json:"currentBranch"`
	CurrentCommit    string          `json:"currentCommit"`
	RecentCommitters []CommitterInfo `json:"recentCommitters"`
	RepoRootPath     string          `json:"repoRootPath"`
	IsDirty          bool            `json:"isDirty"`
}

// CommitterInfo describes a committer with their commit count.
type CommitterInfo struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Count int    `json:"count"`
}

const maxLogCommits = 50

// Collect gathers git context from the repository containing scanPath.
// Returns nil if scanPath is not inside a git repository.
func Collect(scanPath string) *GitContext {
	repo, err := git.PlainOpenWithOptions(scanPath, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return nil
	}

	ctx := &GitContext{}

	// Repo root
	wt, err := repo.Worktree()
	if err == nil {
		ctx.RepoRootPath = wt.Filesystem.Root()
	}

	// Remote URLs
	remotes, err := repo.Remotes()
	if err == nil {
		for _, r := range remotes {
			cfg := r.Config()
			ctx.RemoteURLs = append(ctx.RemoteURLs, cfg.URLs...)
		}
	}

	// HEAD: branch + commit
	head, err := repo.Head()
	if err == nil {
		ctx.CurrentCommit = head.Hash().String()
		if head.Name().IsBranch() {
			ctx.CurrentBranch = head.Name().Short()
		} else if head.Name() == plumbing.HEAD {
			ctx.CurrentBranch = "HEAD (detached)"
		}
	}

	// Recent committers (last N commits)
	logIter, err := repo.Log(&git.LogOptions{})
	if err == nil {
		counts := map[string]*CommitterInfo{}
		n := 0
		logIter.ForEach(func(c *object.Commit) error {
			if n >= maxLogCommits {
				return errStopIter
			}
			n++
			email := strings.ToLower(c.Author.Email)
			if ci, ok := counts[email]; ok {
				ci.Count++
			} else {
				counts[email] = &CommitterInfo{
					Name:  c.Author.Name,
					Email: c.Author.Email,
					Count: 1,
				}
			}
			return nil
		})

		for _, ci := range counts {
			ctx.RecentCommitters = append(ctx.RecentCommitters, *ci)
		}
		sort.Slice(ctx.RecentCommitters, func(i, j int) bool {
			return ctx.RecentCommitters[i].Count > ctx.RecentCommitters[j].Count
		})
	}

	// Dirty state
	if wt != nil {
		status, err := wt.Status()
		if err == nil {
			ctx.IsDirty = !status.IsClean()
		}
	}

	return ctx
}

var errStopIter = &stopIter{}

type stopIter struct{}

func (e *stopIter) Error() string { return "stop" }
