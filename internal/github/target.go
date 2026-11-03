package github

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/vulnetix/cli/v4/internal/gitctx"
)

// Target is the repository, commit and ref a publish applies to.
type Target struct {
	// Repo is owner/name.
	Repo string
	// SHA is the full commit SHA.
	SHA string
	// Ref is the full ref (refs/heads/main, refs/pull/7/merge).
	Ref string
}

// Owner and Name split Repo.
func (t Target) Owner() string { o, _, _ := strings.Cut(t.Repo, "/"); return o }
func (t Target) Name() string  { _, n, _ := strings.Cut(t.Repo, "/"); return n }

// ResolveTarget works out the repository, commit and ref, explicit values
// first, then the GitHub Actions environment (GITHUB_REPOSITORY, GITHUB_SHA,
// GITHUB_REF; on pull_request the merge ref and merge commit, which is what
// code scanning expects), then the git checkout at dir. It errors when any of
// the three is still unknown.
func ResolveTarget(dir, repo, sha, ref string) (Target, error) {
	t := Target{Repo: repo, SHA: sha, Ref: ref}
	if t.Repo == "" {
		t.Repo = os.Getenv("GITHUB_REPOSITORY")
	}
	if t.SHA == "" {
		t.SHA = os.Getenv("GITHUB_SHA")
	}
	if t.Ref == "" {
		t.Ref = os.Getenv("GITHUB_REF")
		// A pull_request_target run's GITHUB_REF is the base branch; the
		// analysed code is the PR's merge ref.
		if os.Getenv("GITHUB_EVENT_NAME") == "pull_request_target" {
			if n := prNumber(os.Getenv("GITHUB_EVENT_PATH")); n > 0 {
				t.Ref = fmt.Sprintf("refs/pull/%d/merge", n)
			}
		}
	}
	if t.Repo == "" || t.SHA == "" || t.Ref == "" {
		if g := gitctx.Collect(dir); g != nil {
			if t.SHA == "" {
				t.SHA = g.CurrentCommit
			}
			if t.Ref == "" && g.CurrentBranch != "" {
				t.Ref = "refs/heads/" + g.CurrentBranch
			}
			if t.Repo == "" {
				for _, u := range g.RemoteURLs {
					if r := RepoFromRemote(u); r != "" {
						t.Repo = r
						break
					}
				}
			}
		}
	}
	if t.Ref != "" && !strings.HasPrefix(t.Ref, "refs/") {
		t.Ref = "refs/heads/" + t.Ref
	}
	var missing []string
	if t.Repo == "" {
		missing = append(missing, "repository (--repo or GITHUB_REPOSITORY)")
	}
	if t.SHA == "" {
		missing = append(missing, "commit (--sha or GITHUB_SHA)")
	}
	if t.Ref == "" {
		missing = append(missing, "ref (--ref or GITHUB_REF)")
	}
	if len(missing) > 0 {
		return t, fmt.Errorf("cannot tell what to publish to: no %s", strings.Join(missing, ", "))
	}
	return t, nil
}

var remoteRe = regexp.MustCompile(`^(?:[^@/]+@[^:]+:|[a-z+]+://[^/]+/)([^/]+/[^/]+?)(?:\.git)?/?$`)

// RepoFromRemote reads owner/name from a git remote URL (https or ssh), or
// returns "".
func RepoFromRemote(remote string) string {
	remote = strings.TrimSpace(remote)
	if u, err := url.Parse(remote); err == nil && u.User != nil && u.Scheme != "" {
		u.User = nil
		remote = u.String()
	}
	m := remoteRe.FindStringSubmatch(remote)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

func prNumber(eventPath string) int {
	if eventPath == "" {
		return 0
	}
	raw, err := os.ReadFile(eventPath)
	if err != nil {
		return 0
	}
	var ev struct {
		PullRequest struct {
			Number int `json:"number"`
		} `json:"pull_request"`
		Number int `json:"number"`
	}
	if json.Unmarshal(raw, &ev) != nil {
		return 0
	}
	if ev.PullRequest.Number > 0 {
		return ev.PullRequest.Number
	}
	return ev.Number
}
