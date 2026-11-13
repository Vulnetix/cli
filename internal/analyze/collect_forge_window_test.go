package analyze

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The forge window can be shorter than the history walk. The compliance pass costs an API
// call a commit, so it asks only about the commits inside the forge window, and never about
// a merge commit, whose review status is its pull request's.
func TestCommitsToReview_StaysInsideTheForgeWindow(t *testing.T) {
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	at := func(days int) string { return now.AddDate(0, 0, -days).Format(time.RFC3339) }
	commits := []*CommitRecord{
		{SHA: "new", CommittedAt: at(1)},
		{SHA: "merge", CommittedAt: at(2), ParentCount: 2},
		{SHA: "edge", CommittedAt: at(7)},
		{SHA: "old", CommittedAt: at(30)},
		{SHA: "undated"},
	}

	require.Equal(t, []string{"new", "edge", "undated"}, commitsToReview(commits, now.AddDate(0, 0, -7)),
		"a commit with no parseable date is kept rather than dropped unseen")
	require.Equal(t, []string{"new", "edge", "old", "undated"}, commitsToReview(commits, now.AddDate(0, 0, -365)))
}

func TestForgeWindowDays_FollowsTheHistoryWindowUnlessSet(t *testing.T) {
	o := DefaultOptions()
	require.Equal(t, 365, o.forgeWindowDays())
	o.ForgeWindowDays = 7
	require.Equal(t, 7, o.forgeWindowDays())
}
