package analyze

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The builder exists so that a collector cannot state a count. These tests pin that: the
// number always comes from the evidence, so the two cannot drift apart.

func TestBuilder_CountDerivesTheValueFromTheEvidence(t *testing.T) {
	b := newTestBuilder()
	refs := []EvidenceRef{SARIFRef(0), SARIFRef(1), SARIFRef(2)}

	b.Count(Metric{ID: "security.secrets.committed", Family: "security", Name: "Secrets",
		Definition: "Secrets in history."}, refs)

	r, _, err := b.Finish(time.Now())
	require.NoError(t, err)
	require.Equal(t, float64(3), r.Metrics[0].Value, "the value must be the number of evidence items, not a number the collector chose")
	require.Len(t, r.Metrics[0].EvidenceRefs, 3)
}

func TestBuilder_TruncationMustBeDeclared(t *testing.T) {
	b := newTestBuilder()
	refs := []EvidenceRef{SARIFRef(0)}

	b.CountTruncated(Metric{ID: "quality.coupling.pairs", Family: "quality", Name: "Pairs",
		Definition: "Co-changing file pairs."}, refs, 99, "pair budget exhausted")

	r, _, err := b.Finish(time.Now())
	require.NoError(t, err)
	require.Equal(t, float64(100), r.Metrics[0].Value, "the value is present plus omitted")
	require.Equal(t, 99, r.Metrics[0].OmittedCount)
	require.NotEmpty(t, r.Metrics[0].TruncationReason)

	// Truncating without saying so is the failure mode the whole format exists to prevent, so
	// there is no way to express it.
	require.Panics(t, func() {
		newTestBuilder().CountTruncated(Metric{ID: "x.y", Family: "quality", Name: "n",
			Definition: "d"}, refs, 5, "")
	}, "a truncated metric with no reason must be impossible to build")
}

func TestBuilder_UnmeasuredIsNullNotZero(t *testing.T) {
	b := newTestBuilder()
	b.Unmeasured(Metric{ID: "security.commit_review.unreviewed", Family: "security",
		Name: "Unreviewed commits", Definition: "Commits that reached the default branch without review."},
		"no forge API access")

	r, _, err := b.Finish(time.Now())
	require.NoError(t, err)
	require.Nil(t, r.Metrics[0].Value, "a metric we could not measure is null; zero would claim we looked and found none")
	require.Empty(t, r.Metrics[0].EvidenceRefs)
	require.Len(t, r.Diagnostics, 1, "and the reason it could not be measured is recorded")
}

// When a collector fails, the metrics it would have produced must still appear — as null. They
// used to be dropped from the report entirely, which is worse than a wrong number: a reader
// notices a number that looks off, and never notices one that is not there.
//
// The forge collector is the one that fails in practice (a token that cannot see a private repo),
// so runForge fills in whatever it did not manage to emit. Has() is what stops it emitting a
// metric the collector already measured a second time.
func TestBuilder_HasReportsWhatWasAlreadyEmitted(t *testing.T) {
	b := newTestBuilder()
	b.Count(Metric{ID: "activity.pull_requests.total", Family: "activity", Name: "Pull requests",
		Definition: "Pull requests in the window."}, []EvidenceRef{})

	require.True(t, b.Has("activity.pull_requests.total"))
	require.False(t, b.Has("activity.issues.total"),
		"a metric the collector never reached is the one the failure path must fill in")
}

// The file walker and the policy checks both describe LICENSE. They must end up describing the
// same record: the evidence store is unique on (run, path), and a second record for a path it
// already holds rejects the entire submission — all 8,000 records, not just the colliding one.
func TestBuilder_AddFileFoldsRecordsForTheSamePath(t *testing.T) {
	b := newTestBuilder()

	first := b.AddFile(&FileRecord{ID: "file-LICENSE", Type: "file", Path: "LICENSE", Language: "text"})
	second := b.AddFile(&FileRecord{ID: "policy-license-file-exists", Type: "file", Path: "LICENSE",
		Tags: []string{"policy", "license-file-exists"}})

	require.Equal(t, first.RecordID, second.RecordID,
		"the policy check must cite the file record that already exists, not mint a rival one")
	require.Len(t, b.records, 1)

	held, ok := b.records[0].(*FileRecord)
	require.True(t, ok)
	require.Equal(t, "text", held.Language, "what the walker knew survives the fold")
	require.Equal(t, []string{"policy", "license-file-exists"}, held.Tags, "and so does what the policy check knew")
}

// The guard is the point: a report that collides on a stored identity is a report that stores
// nothing, so we must not be able to build one.
func TestCheckRecordIdentity_RejectsCollisions(t *testing.T) {
	err := checkRecordIdentity([]any{
		&FileRecord{ID: "file-a", Type: "file", Path: "cmd/a.go"},
		&FileRecord{ID: "policy-x", Type: "file", Path: "cmd/a.go"},
	})
	require.ErrorContains(t, err, "cmd/a.go")
	require.ErrorContains(t, err, "AddFile")

	require.NoError(t, checkRecordIdentity([]any{
		&FileRecord{ID: "file-a", Type: "file", Path: "cmd/a.go"},
		&FileRecord{ID: "file-b", Type: "file", Path: "cmd/b.go"},
		&CommitRecord{ID: "c-1", Type: "commit", SHA: "abc"},
		&CommitRecord{ID: "c-2", Type: "commit", SHA: "def"},
	}))

	require.ErrorContains(t, checkRecordIdentity([]any{
		&CommitRecord{ID: "c-1", Type: "commit", SHA: "abc"},
		&CommitRecord{ID: "c-2", Type: "commit", SHA: "abc"},
	}), "abc")
}

// Finish validates against the schema. A report we would reject on the way in must be one we
// cannot produce on the way out.
func TestBuilder_FinishValidatesAgainstTheSchema(t *testing.T) {
	b := newTestBuilder()
	b.Count(Metric{ID: "activity.commits.total", Family: "activity", Name: "Commits",
		Definition: "Commits in the window."}, []EvidenceRef{})

	_, body, err := b.Finish(time.Now())
	require.NoError(t, err)
	require.NoError(t, ValidateReport(body))
}

// ─── identity ────────────────────────────────────────────────────────────────

func TestClassifyIdentity_Bots(t *testing.T) {
	cases := []struct {
		name, email string
		wantBot     bool
		wantKind    string
	}{
		{"Ada Lovelace", "ada@example.com", false, "none"},
		{"dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com", true, "dependency-bot"},
		{"github-actions[bot]", "github-actions[bot]@users.noreply.github.com", true, "ci"},
		{"renovate[bot]", "renovate[bot]@users.noreply.github.com", true, "dependency-bot"},

		// An AI agent is a bot, but it is not CI. Folding the two together — which DevStats does —
		// answers "is this a human" and throws away "was this written by an agent".
		{"Claude", "claude@anthropic.com", true, "ai-agent"},
		{"Devin", "devin@cognition.ai", true, "ai-agent"},
		{"Copilot", "copilot@github.com", true, "ai-agent"},

		{"", "12345@users.noreply.github.com", true, "numeric-account"},
	}

	for _, c := range cases {
		got := ClassifyIdentity(c.name, c.email)
		require.Equal(t, c.wantBot, got.IsBot, "%s <%s>", c.name, c.email)
		require.Equal(t, c.wantKind, got.BotKind, "%s <%s>", c.name, c.email)
		if got.IsBot {
			require.NotEmpty(t, got.BotRule, "a bot classification must record the rule that made it")
		}
	}
}

func TestClassifyIdentity_ExtractsGitHubLogin(t *testing.T) {
	id := ClassifyIdentity("Ada", "12345+octocat@users.noreply.github.com")
	require.Equal(t, "octocat", id.Login,
		"the login is a fact carried in the address; two identities sharing it are the same person")
}

func TestClassifyIdentity_EmailKind(t *testing.T) {
	require.Equal(t, "personal", ClassifyIdentity("A", "a@gmail.com").EmailKind)
	require.Equal(t, "corporate", ClassifyIdentity("A", "a@acme.io").EmailKind)
	require.Equal(t, "academic", ClassifyIdentity("A", "a@mit.edu").EmailKind)
	require.Equal(t, "noreply", ClassifyIdentity("A", "a@users.noreply.github.com").EmailKind)
}

// Identity merging is a judgement, and a judgement in an evidence-backed report has to show
// its working.
func TestIdentitySet_MergesAndRecordsWhy(t *testing.T) {
	s := NewIdentitySet()
	s.Observe(ClassifyIdentity("Chris Langton", "chris@example.com"))
	s.Observe(ClassifyIdentity("Christopher Langton", "chris@example.com"))

	all := s.All()
	require.Len(t, all, 1, "the same address is the same person")
	require.Len(t, all[0].Aliases, 1)
	require.Equal(t, "normalized-email", all[0].Aliases[0].MergedBy,
		"the rule that merged an alias must be recorded, because it is sometimes wrong")
}

func TestIdentitySet_DoesNotGuessFromNames(t *testing.T) {
	// git-intelligence merges on Levenshtein name similarity >= 0.85, which would merge these
	// two. A wrong merge is invisible in the output; a missed merge is a duplicate row someone
	// can see. We take the visible failure.
	s := NewIdentitySet()
	s.Observe(ClassifyIdentity("Chris Langton", "chris@example.com"))
	s.Observe(ClassifyIdentity("Chris Langtry", "clangtry@example.com"))

	require.Len(t, s.All(), 2, "two different addresses are two people until something proves otherwise")
}

// ─── repository identity ─────────────────────────────────────────────────────

// A repo cloned over SSH and the same repo cloned over HTTPS must produce the same identity,
// or the org graph will show them as two separate repositories that never link up.
func TestParseRemote(t *testing.T) {
	cases := []struct{ remote, host, owner, name string }{
		{"https://github.com/vulnetix/cli.git", "github.com", "vulnetix", "cli"},
		{"https://github.com/vulnetix/cli", "github.com", "vulnetix", "cli"},
		{"git@github.com:vulnetix/cli.git", "github.com", "vulnetix", "cli"},
		{"ssh://git@gitlab.com/acme/team/svc.git", "gitlab.com", "acme/team", "svc"},
		{"git@bitbucket.org:acme/svc.git", "bitbucket.org", "acme", "svc"},
	}
	for _, c := range cases {
		host, owner, name := parseRemote(c.remote)
		require.Equal(t, c.host, host, c.remote)
		require.Equal(t, c.owner, owner, c.remote)
		require.Equal(t, c.name, name, c.remote)
	}
}

// ─── cross-repo join keys ────────────────────────────────────────────────────

// The version is deliberately dropped from a package join key. Repo A depending on
// shared@1.2.0 and repo B publishing shared@1.3.0 are still the same relationship; an org
// graph that only linked exact-version matches would show almost no edges, and the ones it did
// show would be an accident of release timing.
func TestPurlWithoutVersion(t *testing.T) {
	require.Equal(t, "pkg:golang/github.com/spf13/cobra",
		purlWithoutVersion("pkg:golang/github.com/spf13/cobra@1.10.2"))
	require.Equal(t, "pkg:npm/@scope/pkg", purlWithoutVersion("pkg:npm/@scope/pkg@1.0.0"))
	require.Equal(t, "pkg:golang/example.com/x", purlWithoutVersion("pkg:golang/example.com/x"))
}

// ─── statistics ──────────────────────────────────────────────────────────────

// Measure's median helper indexes the middle of an unsorted array and calls the result a
// median. It is not one, and the mistake is invisible in its output.
func TestMedianAndPercentile(t *testing.T) {
	require.Equal(t, 3, median([]int{1, 2, 3, 4, 5}))
	require.Equal(t, 2, median([]int{1, 2, 3, 4}), "even-length inputs average the two middle values")
	require.Equal(t, 0, median(nil))

	require.Equal(t, 9, percentile([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 0.90))
	require.Equal(t, 0, percentile(nil, 0.9))
}

func TestDevelopmentStatus(t *testing.T) {
	require.Equal(t, "Active", developmentStatus(30))
	require.Equal(t, "Aging", developmentStatus(120))
	require.Equal(t, "Stale", developmentStatus(200))
	require.Equal(t, "Unmaintained", developmentStatus(400))
}

func newTestBuilder() *Builder {
	return NewBuilder(
		Tool{Name: "vulnetix-analyze", Version: "test"},
		Target{RepoID: "github.com~vulnetix~cli"},
		time.Now(),
	)
}
