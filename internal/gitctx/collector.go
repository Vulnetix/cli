package gitctx

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// GitContext holds repository metadata collected via go-git.
type GitContext struct {
	RemoteURLs          []string        `json:"remoteUrls"`
	CurrentBranch       string          `json:"currentBranch"`
	CurrentCommit       string          `json:"currentCommit"`
	HeadCommitMessage   string          `json:"headCommitMessage,omitempty"`
	HeadCommitAuthor    string          `json:"headCommitAuthor,omitempty"`
	HeadCommitEmail     string          `json:"headCommitEmail,omitempty"`
	HeadCommitTimestamp string          `json:"headCommitTimestamp,omitempty"`
	HeadTags            []string        `json:"headTags,omitempty"`
	RecentCommitters    []CommitterInfo `json:"recentCommitters"`
	RepoRootPath        string          `json:"repoRootPath"`
	IsDirty             bool            `json:"isDirty"`
	// IsWorktree is true when the repository is opened via a git linked worktree
	// (i.e. the .git entry in the directory root is a file pointer, not the main .git directory).
	IsWorktree bool `json:"isWorktree"`
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

		// Resolve the commit object to read message, author and timestamp.
		if commitObj, cerr := repo.CommitObject(head.Hash()); cerr == nil {
			// Keep only the first line of the commit message.
			msg := strings.TrimSpace(commitObj.Message)
			if idx := strings.IndexByte(msg, '\n'); idx >= 0 {
				msg = strings.TrimSpace(msg[:idx])
			}
			ctx.HeadCommitMessage = msg
			ctx.HeadCommitAuthor = commitObj.Author.Name
			ctx.HeadCommitEmail = commitObj.Author.Email
			ctx.HeadCommitTimestamp = commitObj.Author.When.UTC().Format("2006-01-02T15:04:05Z07:00")
		}

		// Collect any tags pointing at HEAD (lightweight and annotated).
		tagIter, terr := repo.Tags()
		if terr == nil {
			_ = tagIter.ForEach(func(ref *plumbing.Reference) error {
				// Lightweight tag: hash == HEAD commit hash.
				if ref.Hash() == head.Hash() {
					ctx.HeadTags = append(ctx.HeadTags, ref.Name().Short())
					return nil
				}
				// Annotated tag: resolve the tag object and check its target.
				if tagObj, oerr := repo.TagObject(ref.Hash()); oerr == nil {
					if tagObj.Target == head.Hash() {
						ctx.HeadTags = append(ctx.HeadTags, ref.Name().Short())
					}
				}
				return nil
			})
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

	// Linked worktree detection: in a linked worktree the .git entry inside the
	// working-tree root is a plain file ("gitdir: ..."), not the main .git directory.
	if ctx.RepoRootPath != "" {
		gitEntry := filepath.Join(ctx.RepoRootPath, ".git")
		if fi, sterr := os.Stat(gitEntry); sterr == nil {
			ctx.IsWorktree = !fi.IsDir()
		}
	}

	return ctx
}

var errStopIter = &stopIter{}

type stopIter struct{}

func (e *stopIter) Error() string { return "stop" }
