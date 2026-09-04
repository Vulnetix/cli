package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// initGitRepo makes a throwaway repository in a temp dir and leaves the test
// chdir'd into it. gitDescribeVersion shells out to git in the working
// directory, which in a workflow is the checkout, so the test uses a real
// repository rather than stubbing the command out.
func initGitRepo(t *testing.T, tag string, extraCommits int) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run("init", "-q", "-b", "main")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
	// The developer's global config sets commit.gpgsign=true. Signing a commit
	// in a throwaway repository would prompt or fail, so it is turned off here.
	run("config", "commit.gpgsign", "false")
	run("commit", "-q", "--allow-empty", "-m", "initial")
	if tag != "" {
		run("tag", tag)
	}
	for i := 0; i < extraCommits; i++ {
		run("commit", "-q", "--allow-empty", "-m", "more")
	}
}

// A repository with a tag describes as that tag plus the distance to HEAD,
// which is what makes the version sort after the release it descends from.
func TestGitDescribeVersion_TaggedRepo(t *testing.T) {
	initGitRepo(t, "v1.0.0", 2)

	got, err := gitDescribeVersion()
	if err != nil {
		t.Fatal(err)
	}
	want := regexp.MustCompile(`^v1\.0\.0-2-g[0-9a-f]{7,}$`)
	if !want.MatchString(got) {
		t.Errorf("got %q, want something like v1.0.0-2-gabc1234", got)
	}
}

// Exactly on the tag, a branch-derived version must still carry a commit suffix.
// Auto Version can tag the commit while a slower branch security run is still
// executing; returning the bare tag there would make that pre-release collide
// with the final release workflow's object.
func TestGitDescribeVersion_OnTheTag(t *testing.T) {
	initGitRepo(t, "v1.0.0", 0)

	got, err := gitDescribeVersion()
	if err != nil {
		t.Fatal(err)
	}
	want := regexp.MustCompile(`^v1\.0\.0-0-g[0-9a-f]{7,}$`)
	if !want.MatchString(got) {
		t.Errorf("got %q, want something like v1.0.0-0-gabc1234", got)
	}
}

// Most repositories in the fleet have no tags at all. --always makes that a
// short SHA rather than an error, so those repositories still publish.
func TestGitDescribeVersion_NoTags(t *testing.T) {
	initGitRepo(t, "", 0)

	got, err := gitDescribeVersion()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{7,}$`).MatchString(got) {
		t.Errorf("got %q, want a short SHA", got)
	}
}

// The derived date is HEAD's committer date, not the moment the test runs.
// git already reports a UTC-normalised instant here because the local clock
// used to create the commit and the config below have no explicit offset, so
// this pins the value against git's own answer rather than a hard-coded
// string.
func TestGitCommitDate_MatchesHeadCommitterDate(t *testing.T) {
	initGitRepo(t, "", 0)

	want, err := exec.Command("git", "log", "-1", "--format=%cI").Output()
	if err != nil {
		t.Fatal(err)
	}
	wantTime, err := time.Parse(time.RFC3339, strings.TrimSpace(string(want)))
	if err != nil {
		t.Fatal(err)
	}

	got, err := gitCommitDate("")
	if err != nil {
		t.Fatal(err)
	}
	if got != wantTime.UTC().Format(time.RFC3339) {
		t.Errorf("got %q, want %q", got, wantTime.UTC().Format(time.RFC3339))
	}
}

// The actual regression guard: a stable idempotency key paired with an
// unstable body is what broke production. Two calls against the same HEAD
// must produce the exact same string, or CreateProductRelease's re-run would
// fail with VERSION_CONFLICT all over again.
func TestGitCommitDate_DeterministicAcrossCalls(t *testing.T) {
	initGitRepo(t, "", 0)

	first, err := gitCommitDate("")
	if err != nil {
		t.Fatal(err)
	}
	second, err := gitCommitDate("")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("first call %q, second call %q, want identical", first, second)
	}
}

// A committer date with a positive, non-UTC offset must convert to the
// correct UTC instant, not just have its offset stripped. Getting the sign or
// the arithmetic wrong here reintroduces the original bug in a subtler form:
// two clones in different timezones would again disagree on the release date
// of the same commit.
func TestGitCommitDate_NormalisesNonUTCOffset(t *testing.T) {
	initGitRepo(t, "", 0)

	commit := exec.Command("git", "commit", "--allow-empty", "-m", "second",
		"--date", "2026-08-02T15:57:06+10:00")
	commit.Env = append(os.Environ(), "GIT_COMMITTER_DATE=2026-08-02T15:57:06+10:00")
	if out, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}

	got, err := gitCommitDate("")
	if err != nil {
		t.Fatal(err)
	}
	// 15:57:06+10:00 is 10 hours ahead of UTC, so the UTC instant is 05:57:06.
	if want := "2026-08-02T05:57:06Z"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// An explicit --version is the caller saying what the release is called. It
// must beat anything derived, or a pipeline could not override a bad describe.
func TestResolveTeaReleaseInputs_ExplicitVersionWinsOverAutoVersion(t *testing.T) {
	initGitRepo(t, "v1.0.0", 3)
	t.Setenv("GITHUB_REPOSITORY", "Vulnetix/cli")
	t.Setenv("GITHUB_REF_TYPE", "branch")

	cmd := newTeaReleaseCommand()
	if err := cmd.Flags().Set("auto-version", "true"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("version", "v9.9.9"); err != nil {
		t.Fatal(err)
	}

	in, err := resolveTeaReleaseInputs(cmd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if in.Version != "v9.9.9" {
		t.Errorf("version %q, want v9.9.9", in.Version)
	}
	if in.PreRelease {
		t.Error("an explicit version must not be forced to pre-release")
	}
}

// The tag is the release. --auto-version must not turn a tagged run into a
// pre-release, or every real release would be published as one.
func TestResolveTeaReleaseInputs_TagRunIsNotPreRelease(t *testing.T) {
	initGitRepo(t, "v1.0.0", 0)
	t.Setenv("GITHUB_REPOSITORY", "Vulnetix/cli")
	t.Setenv("GITHUB_REF_TYPE", "tag")
	t.Setenv("GITHUB_REF_NAME", "v2.0.0")

	cmd := newTeaReleaseCommand()
	if err := cmd.Flags().Set("auto-version", "true"); err != nil {
		t.Fatal(err)
	}

	in, err := resolveTeaReleaseInputs(cmd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if in.Version != "v2.0.0" {
		t.Errorf("version %q, want the tag v2.0.0", in.Version)
	}
	if in.PreRelease {
		t.Error("a tag run must not be marked pre-release")
	}
}

// A branch push is not a release. It still publishes, under a derived version,
// flagged so a consumer can tell the two apart.
func TestResolveTeaReleaseInputs_BranchRunIsPreRelease(t *testing.T) {
	initGitRepo(t, "v1.0.0", 2)
	t.Setenv("GITHUB_REPOSITORY", "Vulnetix/cli")
	t.Setenv("GITHUB_REF_TYPE", "branch")
	t.Setenv("GITHUB_REF_NAME", "main")

	cmd := newTeaReleaseCommand()
	if err := cmd.Flags().Set("auto-version", "true"); err != nil {
		t.Fatal(err)
	}

	in, err := resolveTeaReleaseInputs(cmd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^v1\.0\.0-2-g[0-9a-f]{7,}$`).MatchString(in.Version) {
		t.Errorf("version %q, want a describe string", in.Version)
	}
	if !in.PreRelease {
		t.Error("a non-tag run must be marked pre-release")
	}
}

// Without the flag, nothing changes. cli/release.yml depends on this.
func TestResolveTeaReleaseInputs_WithoutAutoVersionBranchStillErrors(t *testing.T) {
	initGitRepo(t, "v1.0.0", 2)
	t.Setenv("GITHUB_REPOSITORY", "Vulnetix/cli")
	t.Setenv("GITHUB_REF_TYPE", "branch")

	cmd := newTeaReleaseCommand()
	if _, err := resolveTeaReleaseInputs(cmd, nil); err == nil {
		t.Fatal("want an error when no version is available and --auto-version is off")
	}
}

// An explicit --date is the caller overriding what git would derive. It must
// win unconditionally, the same as --version does.
func TestResolveTeaReleaseInputs_ExplicitDateWinsOverCommitDate(t *testing.T) {
	initGitRepo(t, "v1.0.0", 0)
	t.Setenv("GITHUB_REPOSITORY", "Vulnetix/cli")
	t.Setenv("GITHUB_REF_TYPE", "tag")
	t.Setenv("GITHUB_REF_NAME", "v1.0.0")

	cmd := newTeaReleaseCommand()
	if err := cmd.Flags().Set("date", "1999-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}

	in, err := resolveTeaReleaseInputs(cmd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if in.Date != "1999-01-01T00:00:00Z" {
		t.Errorf("date %q, want the explicit --date unchanged", in.Date)
	}
}

// Without --date, the release date is HEAD's committer date, and it must not
// move between calls against the same commit. This is the production bug:
// CreateProductRelease and CreateComponentRelease send this value under a
// stable idempotency key, so a re-run that derives a different date on every
// call cannot ever republish, it can only conflict.
func TestResolveTeaReleaseInputs_DateDefaultsToCommitDateAndIsStable(t *testing.T) {
	initGitRepo(t, "v1.0.0", 0)
	t.Setenv("GITHUB_REPOSITORY", "Vulnetix/cli")
	t.Setenv("GITHUB_REF_TYPE", "tag")
	t.Setenv("GITHUB_REF_NAME", "v1.0.0")

	wantDate, err := gitCommitDate("")
	if err != nil {
		t.Fatal(err)
	}

	cmd := newTeaReleaseCommand()
	first, err := resolveTeaReleaseInputs(cmd, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := resolveTeaReleaseInputs(cmd, nil)
	if err != nil {
		t.Fatal(err)
	}

	if first.Date != wantDate {
		t.Errorf("date %q, want the committer date %q", first.Date, wantDate)
	}
	if first.Date != second.Date {
		t.Errorf("first call %q, second call %q, want identical across re-runs", first.Date, second.Date)
	}
}

// An explicit --checksums is the caller naming the file. Nothing derived may
// override it.
func TestResolveChecksumsManifest_ExplicitWins(t *testing.T) {
	manifest := writeTeaTemp(t, "checksums.txt", "b9f62ff7  tool\n")

	cmd := newTeaReleaseCommand()
	if err := cmd.Flags().Set("checksums", manifest); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("checksums-from-release", "true"); err != nil {
		t.Fatal(err)
	}

	got, err := resolveChecksumsManifest(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if got != manifest {
		t.Errorf("got %q, want the explicit path %q", got, manifest)
	}
}

// A branch push has no GitHub release to read. That is the common case across
// the fleet and must not be an error: the run publishes evidence with no
// download links.
func TestResolveChecksumsManifest_NonTagRunResolvesToNothing(t *testing.T) {
	t.Setenv("GITHUB_REF_TYPE", "branch")

	cmd := newTeaReleaseCommand()
	if err := cmd.Flags().Set("checksums-from-release", "true"); err != nil {
		t.Fatal(err)
	}

	got, err := resolveChecksumsManifest(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("got %q, want no manifest on a branch run", got)
	}
}

// A tag release that ships no checksums file is legitimate. Publish the
// evidence, skip the distributions, do not fail the job.
func TestResolveChecksumsManifest_NoMatchingAssetResolvesToNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v1.0.0","assets":[{"name":"tool-linux-amd64","browser_download_url":"http://x/y"}]}`))
	}))
	defer srv.Close()

	t.Setenv("GITHUB_REF_TYPE", "tag")
	t.Setenv("GITHUB_REF_NAME", "v1.0.0")
	t.Setenv("GITHUB_REPOSITORY", "Vulnetix/cli")
	t.Setenv("GITHUB_API_URL", srv.URL)
	t.Setenv("GITHUB_TOKEN", "tok")

	cmd := newTeaReleaseCommand()
	if err := cmd.Flags().Set("checksums-from-release", "true"); err != nil {
		t.Fatal(err)
	}

	got, err := resolveChecksumsManifest(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("got %q, want nothing when the release has no checksums asset", got)
	}
}

// The whole point: on a tag run the manifest is fetched and its path returned.
func TestResolveChecksumsManifest_FetchesTheAsset(t *testing.T) {
	const body = "b9f62ff7cb04a2ff7418f11d7777e060b09820ad3ee5b60ed45439d433d70a7e  tool-linux-amd64\n"

	mux := http.NewServeMux()
	mux.HandleFunc("/download/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/repos/Vulnetix/cli/releases/tags/v1.0.0", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v1.0.0","assets":[{"name":"checksums.txt","browser_download_url":"` +
			srv.URL + `/download/checksums.txt"}]}`))
	})

	t.Setenv("GITHUB_REF_TYPE", "tag")
	t.Setenv("GITHUB_REF_NAME", "v1.0.0")
	t.Setenv("GITHUB_REPOSITORY", "Vulnetix/cli")
	t.Setenv("GITHUB_API_URL", srv.URL)
	t.Setenv("GITHUB_TOKEN", "tok")

	cmd := newTeaReleaseCommand()
	if err := cmd.Flags().Set("checksums-from-release", "true"); err != nil {
		t.Fatal(err)
	}

	got, err := resolveChecksumsManifest(cmd)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != body {
		t.Errorf("content %q", b)
	}
}

// Off by default, so cli/release.yml keeps passing --checksums by hand.
func TestResolveChecksumsManifest_OffByDefault(t *testing.T) {
	t.Setenv("GITHUB_REF_TYPE", "tag")
	t.Setenv("GITHUB_REF_NAME", "v1.0.0")

	cmd := newTeaReleaseCommand()
	got, err := resolveChecksumsManifest(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("got %q, want nothing without the flag", got)
	}
}

// TestGitCommitDate_StableWhenHeadMovesPastTheTag is the regression this
// function actually needed.
//
// Determinism at one HEAD was already covered, and that is precisely why the
// bug shipped: the release body carries the date while the idempotency key does
// not, so what has to be stable is the date *for a given release*, across every
// checkout it might be published from. v3.103.0 was cut at its tag, its publish
// failed on an unrelated transient, and the documented recovery ran one commit
// later — sending a different body under the same key, which the server refused
// with VERSION_CONFLICT.
func TestGitCommitDate_StableWhenHeadMovesPastTheTag(t *testing.T) {
	initGitRepo(t, "v9.9.9", 0)

	atTag, err := gitCommitDate("v9.9.9")
	if err != nil {
		t.Fatal(err)
	}

	// Land another commit, as any repository does between a release and the
	// moment somebody has to repair its publish. The date is pinned rather than
	// left to the clock: two commits made in the same second share a committer
	// date, and the assertion below would then pass without testing anything.
	later := exec.Command("git", "commit", "-q", "--allow-empty", "-m", "later work")
	later.Env = append(os.Environ(),
		"GIT_COMMITTER_DATE=2030-01-01T12:00:00+00:00",
		"GIT_AUTHOR_DATE=2030-01-01T12:00:00+00:00",
	)
	if out, err := later.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}

	fromHead, err := gitCommitDate("")
	if err != nil {
		t.Fatal(err)
	}
	if fromHead == atTag {
		t.Fatal("test setup failed: HEAD did not move to a different committer date")
	}

	afterMove, err := gitCommitDate("v9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if afterMove != atTag {
		t.Errorf("date changed when HEAD moved past the tag: at tag %q, after %q (HEAD is %q)",
			atTag, afterMove, fromHead)
	}
}

// An unknown tag is not an error: a release may legitimately be published
// before its tag exists, and a shallow clone may not have fetched tags at all.
func TestGitCommitDate_FallsBackWhenTagIsUnknown(t *testing.T) {
	initGitRepo(t, "", 0)

	got, err := gitCommitDate("v0.0.0-does-not-exist")
	if err != nil {
		t.Fatalf("an unresolvable tag must fall back to HEAD, got %v", err)
	}
	head, err := gitCommitDate("")
	if err != nil {
		t.Fatal(err)
	}
	if got != head {
		t.Errorf("got %q, want HEAD's date %q", got, head)
	}
}
