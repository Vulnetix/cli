package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
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

// Exactly on the tag, describe returns the bare tag. That is the same string a
// tag-triggered run would use, so the two paths agree.
func TestGitDescribeVersion_OnTheTag(t *testing.T) {
	initGitRepo(t, "v1.0.0", 0)

	got, err := gitDescribeVersion()
	if err != nil {
		t.Fatal(err)
	}
	if got != "v1.0.0" {
		t.Errorf("got %q, want v1.0.0", got)
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
