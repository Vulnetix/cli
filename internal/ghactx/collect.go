package ghactx

import (
	"context"
	"os"
	"strconv"

	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// Provider identifies the CI system in the collected context.
const Provider = "github-actions"

// RESTLookup is the subset of the GitHub artifact collector this package uses
// to fill gaps. Declared as an interface so the collector stays testable and so
// this package does not depend on the artifact download machinery.
type RESTLookup interface {
	GetWorkflowRun(ctx context.Context) (*RunInfo, error)
	GetRepository(ctx context.Context) (*RepoInfo, error)
	ListPullsForCommit(ctx context.Context, sha string) ([]PullInfo, error)
}

// RunInfo, RepoInfo and PullInfo mirror the REST shapes without importing them,
// so a caller can adapt any client.
type RunInfo struct {
	RunNumber       int
	RunAttempt      int
	Event           string
	HeadBranch      string
	HeadSHA         string
	HTMLURL         string
	Name            string
	Actor           string
	TriggeringActor string
	PullRequest     int
}

type RepoInfo struct {
	ID            int64
	Visibility    string
	DefaultBranch string
	OwnerType     string
	LicenseSpdxID string
}

type PullInfo struct {
	Number  int
	State   string
	BaseRef string
	HeadRef string
}

// Options controls how much effort collection puts in.
type Options struct {
	// NoAPI suppresses every network lookup. Environment variables and the
	// event payload on disk are still read.
	NoAPI bool
	// Lookup performs the REST fallbacks. Nil disables them, same as NoAPI.
	Lookup RESTLookup
	// Warn receives a note whenever an optional lookup failed, so a degraded
	// context is visible in the workflow log rather than silently thinner.
	Warn func(format string, args ...any)
}

// Collect builds the CI context, cheapest source first.
//
//	Tier 0  environment variables      free
//	Tier 1  GITHUB_EVENT_PATH          free, on disk, and the richest source
//	Tier 2  GitHub REST                one call each, only for what is still missing
//
// Returns nil outside a GitHub Actions runner.
func Collect(ctx context.Context, opt Options) *vdb.CliCIContext {
	if os.Getenv("GITHUB_ACTIONS") != "true" && os.Getenv("GITHUB_RUN_ID") == "" {
		return nil
	}

	c := &vdb.CliCIContext{
		Provider:        Provider,
		Repository:      os.Getenv("GITHUB_REPOSITORY"),
		RepositoryOwner: os.Getenv("GITHUB_REPOSITORY_OWNER"),
		RunID:           envInt64("GITHUB_RUN_ID"),
		RunNumber:       envInt("GITHUB_RUN_NUMBER"),
		RunAttempt:      envInt("GITHUB_RUN_ATTEMPT"),
		WorkflowName:    os.Getenv("GITHUB_WORKFLOW"),
		WorkflowRef:     os.Getenv("GITHUB_WORKFLOW_REF"),
		WorkflowSHA:     os.Getenv("GITHUB_WORKFLOW_SHA"),
		JobName:         os.Getenv("GITHUB_JOB"),
		EventName:       os.Getenv("GITHUB_EVENT_NAME"),
		Ref:             os.Getenv("GITHUB_REF"),
		RefName:         os.Getenv("GITHUB_REF_NAME"),
		RefType:         os.Getenv("GITHUB_REF_TYPE"),
		HeadRef:         os.Getenv("GITHUB_HEAD_REF"),
		BaseRef:         os.Getenv("GITHUB_BASE_REF"),
		SHA:             os.Getenv("GITHUB_SHA"),
		Actor:           os.Getenv("GITHUB_ACTOR"),
		TriggeringActor: os.Getenv("GITHUB_TRIGGERING_ACTOR"),
		ServerURL:       os.Getenv("GITHUB_SERVER_URL"),
		APIURL:          os.Getenv("GITHUB_API_URL"),
		Workspace:       os.Getenv("GITHUB_WORKSPACE"),
		RunnerOS:        os.Getenv("RUNNER_OS"),
		RunnerArch:      os.Getenv("RUNNER_ARCH"),
		RunnerName:      os.Getenv("RUNNER_NAME"),
	}
	if c.RunAttempt == 0 {
		c.RunAttempt = 1
	}
	if c.ServerURL != "" && c.Repository != "" && c.RunID > 0 {
		c.RunURL = c.ServerURL + "/" + c.Repository + "/actions/runs/" + strconv.FormatInt(c.RunID, 10)
	}

	applyEvent(c, LoadEvent())

	if !opt.NoAPI && opt.Lookup != nil {
		applyREST(ctx, c, opt)
	}
	return c
}

// applyEvent fills from the webhook payload GitHub wrote to disk.
//
// This is the highest-value source in the whole collector: repository id,
// visibility, default branch, licence and owner type appear nowhere in the
// environment, and on a pull_request event the PR number and both refs are here
// too — all without a network call.
func applyEvent(c *vdb.CliCIContext, e *Event) {
	if e == nil {
		return
	}

	if c.RepositoryID == 0 {
		c.RepositoryID = e.Int64("repository", "id")
	}
	setIfEmpty(&c.Repository, e.String("repository", "full_name"))
	setIfEmpty(&c.RepositoryOwner, e.String("repository", "owner", "login"))
	setIfEmpty(&c.OwnerType, e.String("repository", "owner", "type"))
	setIfEmpty(&c.DefaultBranch, e.String("repository", "default_branch"))
	setIfEmpty(&c.LicenseSpdxID, e.String("repository", "license", "spdx_id"))

	// visibility is absent on older payloads; the private boolean is not.
	if c.Visibility == "" {
		if v := e.String("repository", "visibility"); v != "" {
			c.Visibility = v
		} else if e.Has("repository", "private") {
			if e.Bool("repository", "private") {
				c.Visibility = "private"
			} else {
				c.Visibility = "public"
			}
		}
	}

	if e.Has("pull_request") {
		if n := e.Int("pull_request", "number"); n > 0 && c.PullRequestNumber == 0 {
			c.PullRequestNumber = n
		}
		setIfEmpty(&c.BaseRef, e.String("pull_request", "base", "ref"))
		setIfEmpty(&c.HeadRef, e.String("pull_request", "head", "ref"))
		// On a pull_request event GITHUB_SHA is the merge commit, which does not
		// exist in the contributor's branch. The head sha is the commit the
		// findings actually describe.
		if sha := e.String("pull_request", "head", "sha"); sha != "" {
			c.SHA = sha
		}
	}

	// A workflow_run event describes another run, not this one; take only the
	// fields that are unambiguous.
	if e.Has("workflow_run") {
		setIfEmpty(&c.HeadRef, e.String("workflow_run", "head_branch"))
	}
}

// applyREST fills what neither the environment nor the event payload provided.
// Every failure is a warning: a thinner context is worse than a complete one,
// but far better than a failed publish.
func applyREST(ctx context.Context, c *vdb.CliCIContext, opt Options) {
	warn := opt.Warn
	if warn == nil {
		warn = func(string, ...any) {}
	}

	// Repository metadata is missing only when there was no event payload —
	// workflow_dispatch and schedule runs, mainly.
	if c.RepositoryID == 0 || c.DefaultBranch == "" || c.Visibility == "" {
		if repo, err := opt.Lookup.GetRepository(ctx); err != nil {
			warn("could not read repository metadata: %v", err)
		} else if repo != nil {
			if c.RepositoryID == 0 {
				c.RepositoryID = repo.ID
			}
			setIfEmpty(&c.Visibility, repo.Visibility)
			setIfEmpty(&c.DefaultBranch, repo.DefaultBranch)
			setIfEmpty(&c.OwnerType, repo.OwnerType)
			setIfEmpty(&c.LicenseSpdxID, repo.LicenseSpdxID)
		}
	}

	// The run lookup settles the attempt number and the actor on a re-run, where
	// the environment can disagree with what actually happened.
	if c.RunNumber == 0 || c.TriggeringActor == "" || c.EventName == "" {
		if run, err := opt.Lookup.GetWorkflowRun(ctx); err != nil {
			warn("could not read workflow run metadata: %v", err)
		} else if run != nil {
			if c.RunNumber == 0 {
				c.RunNumber = run.RunNumber
			}
			if run.RunAttempt > 0 {
				c.RunAttempt = run.RunAttempt
			}
			setIfEmpty(&c.EventName, run.Event)
			setIfEmpty(&c.HeadRef, run.HeadBranch)
			setIfEmpty(&c.SHA, run.HeadSHA)
			setIfEmpty(&c.RunURL, run.HTMLURL)
			setIfEmpty(&c.Actor, run.Actor)
			setIfEmpty(&c.TriggeringActor, run.TriggeringActor)
			if c.PullRequestNumber == 0 && run.PullRequest > 0 {
				c.PullRequestNumber = run.PullRequest
			}
		}
	}

	// A push to a branch with an open PR carries no PR number anywhere else.
	if c.PullRequestNumber == 0 && c.SHA != "" {
		if pulls, err := opt.Lookup.ListPullsForCommit(ctx, c.SHA); err != nil {
			warn("could not resolve pull requests for %s: %v", short(c.SHA), err)
		} else {
			for _, p := range pulls {
				if p.State == "open" {
					c.PullRequestNumber = p.Number
					setIfEmpty(&c.BaseRef, p.BaseRef)
					setIfEmpty(&c.HeadRef, p.HeadRef)
					break
				}
			}
		}
	}
}

func setIfEmpty(dst *string, v string) {
	if *dst == "" && v != "" {
		*dst = v
	}
}

func envInt(key string) int {
	n, _ := strconv.Atoi(os.Getenv(key))
	return n
}

func envInt64(key string) int64 {
	n, _ := strconv.ParseInt(os.Getenv(key), 10, 64)
	return n
}

func short(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}
