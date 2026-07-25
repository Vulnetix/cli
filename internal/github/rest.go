package github

// Read-only GitHub REST lookups used to fill gaps in the CI context that the
// environment and the webhook payload on disk leave open.
//
// These are fallbacks, not the primary source. GITHUB_EVENT_PATH already
// contains the whole webhook payload for push and pull_request events, which is
// where the repository and PR details come from at zero cost. The API is only
// worth a round trip for workflow_dispatch / schedule runs (no event payload
// worth reading) and for re-runs, where the environment's run attempt is the
// only clue that the numbers moved.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// restTimeout bounds the metadata lookups. The collector's own client is set up
// for 1 GB artifact downloads, which is far too patient for a metadata call
// whose result is optional.
const restTimeout = 15 * time.Second

// WorkflowRun is the subset of GET /repos/{repo}/actions/runs/{id} worth keeping.
type WorkflowRun struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	RunNumber       int    `json:"run_number"`
	RunAttempt      int    `json:"run_attempt"`
	Event           string `json:"event"`
	Status          string `json:"status"`
	Conclusion      string `json:"conclusion"`
	HeadBranch      string `json:"head_branch"`
	HeadSHA         string `json:"head_sha"`
	HTMLURL         string `json:"html_url"`
	Path            string `json:"path"`
	Actor           *User  `json:"actor"`
	TriggeringActor *User  `json:"triggering_actor"`
	PullRequests    []struct {
		Number int `json:"number"`
	} `json:"pull_requests"`
}

// User is a GitHub account reference.
type User struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}

// Repository is the subset of GET /repos/{repo} worth keeping.
type Repository struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	Visibility    string `json:"visibility"`
	DefaultBranch string `json:"default_branch"`
	Owner         *User  `json:"owner"`
	License       *struct {
		SpdxID string `json:"spdx_id"`
	} `json:"license"`
}

// PullRequestRef is one PR a commit belongs to.
type PullRequestRef struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	Base   struct {
		Ref string `json:"ref"`
	} `json:"base"`
	Head struct {
		Ref string `json:"ref"`
	} `json:"head"`
}

// GetWorkflowRun fetches this run's metadata.
func (c *ArtifactCollector) GetWorkflowRun(ctx context.Context) (*WorkflowRun, error) {
	var run WorkflowRun
	url := fmt.Sprintf("%s/repos/%s/actions/runs/%s", c.apiURL, c.repository, c.runID)
	if err := c.getJSON(ctx, url, &run); err != nil {
		return nil, err
	}
	return &run, nil
}

// GetRepository fetches the repository's metadata.
func (c *ArtifactCollector) GetRepository(ctx context.Context) (*Repository, error) {
	var repo Repository
	url := fmt.Sprintf("%s/repos/%s", c.apiURL, c.repository)
	if err := c.getJSON(ctx, url, &repo); err != nil {
		return nil, err
	}
	return &repo, nil
}

// ListPullsForCommit finds the pull requests a commit belongs to. Used on a push
// to a branch that has an open PR, where the event payload carries no PR number.
func (c *ArtifactCollector) ListPullsForCommit(ctx context.Context, sha string) ([]PullRequestRef, error) {
	if sha == "" {
		return nil, fmt.Errorf("commit sha required")
	}
	var pulls []PullRequestRef
	url := fmt.Sprintf("%s/repos/%s/commits/%s/pulls", c.apiURL, c.repository, sha)
	if err := c.getJSON(ctx, url, &pulls); err != nil {
		return nil, err
	}
	return pulls, nil
}

// getJSON performs an authenticated GET and decodes the body.
func (c *ArtifactCollector) getJSON(ctx context.Context, url string, out any) error {
	if c.token == "" {
		return fmt.Errorf("GitHub token is required. Set GITHUB_TOKEN environment variable")
	}
	ctx, cancel := context.WithTimeout(ctx, restTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API %s: HTTP %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
