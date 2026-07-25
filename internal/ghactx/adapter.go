package ghactx

import (
	"context"

	"github.com/vulnetix/cli/v3/internal/github"
)

// CollectorLookup adapts *github.ArtifactCollector to RESTLookup. It lives here
// rather than in the github package so ghactx owns the shape it needs and the
// artifact downloader stays unaware of CI context.
type CollectorLookup struct {
	Collector *github.ArtifactCollector
}

// GetWorkflowRun implements RESTLookup.
func (l CollectorLookup) GetWorkflowRun(ctx context.Context) (*RunInfo, error) {
	run, err := l.Collector.GetWorkflowRun(ctx)
	if err != nil || run == nil {
		return nil, err
	}
	info := &RunInfo{
		RunNumber:  run.RunNumber,
		RunAttempt: run.RunAttempt,
		Event:      run.Event,
		HeadBranch: run.HeadBranch,
		HeadSHA:    run.HeadSHA,
		HTMLURL:    run.HTMLURL,
		Name:       run.Name,
	}
	if run.Actor != nil {
		info.Actor = run.Actor.Login
	}
	if run.TriggeringActor != nil {
		info.TriggeringActor = run.TriggeringActor.Login
	}
	if len(run.PullRequests) > 0 {
		info.PullRequest = run.PullRequests[0].Number
	}
	return info, nil
}

// GetRepository implements RESTLookup.
func (l CollectorLookup) GetRepository(ctx context.Context) (*RepoInfo, error) {
	repo, err := l.Collector.GetRepository(ctx)
	if err != nil || repo == nil {
		return nil, err
	}
	info := &RepoInfo{
		ID:            repo.ID,
		Visibility:    repo.Visibility,
		DefaultBranch: repo.DefaultBranch,
	}
	if info.Visibility == "" {
		if repo.Private {
			info.Visibility = "private"
		} else {
			info.Visibility = "public"
		}
	}
	if repo.Owner != nil {
		info.OwnerType = repo.Owner.Type
	}
	if repo.License != nil {
		info.LicenseSpdxID = repo.License.SpdxID
	}
	return info, nil
}

// ListPullsForCommit implements RESTLookup.
func (l CollectorLookup) ListPullsForCommit(ctx context.Context, sha string) ([]PullInfo, error) {
	pulls, err := l.Collector.ListPullsForCommit(ctx, sha)
	if err != nil {
		return nil, err
	}
	out := make([]PullInfo, 0, len(pulls))
	for _, p := range pulls {
		out = append(out, PullInfo{
			Number:  p.Number,
			State:   p.State,
			BaseRef: p.Base.Ref,
			HeadRef: p.Head.Ref,
		})
	}
	return out, nil
}
