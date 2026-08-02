# TEA Release Rollout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish every repository's SBOM, CBOM and AI-BOM to the Transparency Exchange API on every push, tag and GitHub release.

**Architecture:** Two opt-in flags are added to `vulnetix tea release` so all conditional logic (tag versus branch, missing tags, missing checksums asset) is Go code covered by Go tests. A single `workflow_call` workflow in the public `cli` repository then calls the CLI with no branching shell of its own, and each of the 25 repositories that run `vulnetix.yml` gains a small caller job.

**Tech Stack:** Go 1.25, Cobra, GitHub Actions, `actionlint`, `just`.

**Spec:** `docs/superpowers/specs/2026-08-03-tea-release-rollout-design.md`

## Global Constraints

- Trunk-based development. Commit directly to `main` in every repository. Never create a branch, never open a pull request.
- No `Co-Authored-By` or `Claude-Session` trailers in any commit message.
- No em-dashes in any prose written to a file.
- Both new CLI flags are opt-in. `cli/.github/workflows/release.yml` must keep behaving exactly as it does today; do not edit that file.
- `--visibility public` is irreversible. It is passed only by the eight repositories that are public on GitHub: `cli`, `homebrew-tap`, `scoop-bucket`, `pix-ai-coding-assistant`, `vdb-cyclonedx`, `ietf-crit-spec`, `transparency-exchange-api`, `malscan-engine`. Every other caller omits the input entirely.
- `tea-spec` is excluded from the rollout. It is a fork of a third-party specification and has no `vulnetix.yml`.
- Run `just fmt` before every commit that touches Go, and `just test` before every commit in `cli`.

---

### Task 1: `--auto-version` on `tea release`

Version resolution today errors on a non-tag run. This adds a fallback to `git describe --tags --always`, which sorts after the release it descends from and resolves back to a commit.

**Files:**
- Modify: `cli/cmd/tea_release.go` (`newTeaReleaseCommand`, `resolveTeaReleaseInputs`)
- Test: `cli/cmd/tea_release_test.go` (create)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `gitDescribeVersion() (string, error)` in package `cmd`; a `--auto-version` bool flag on `tea release`. Task 3 calls the flag from YAML.

- [ ] **Step 1: Write the failing test**

Create `cli/cmd/tea_release_test.go`:

```go
package cmd

import (
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/chris/GitHub/Vulnetix/cli && go test ./cmd/ -run 'TeaRelease|GitDescribe' -v`
Expected: FAIL to compile, `undefined: gitDescribeVersion`, and `flag accessed but not defined: auto-version`.

- [ ] **Step 3: Add the flag**

In `cli/cmd/tea_release.go`, inside `newTeaReleaseCommand`, immediately after the existing `cmd.Flags().String("version", ...)` line:

```go
	cmd.Flags().Bool("auto-version", false,
		"outside a tag run, derive the version from `git describe` and mark it a pre-release")
```

- [ ] **Step 4: Add `gitDescribeVersion`**

Append to `cli/cmd/tea_release.go`:

```go
// gitDescribeVersion names the current commit relative to the last tag.
//
// `v3.75.0-12-gabc1234` sorts after the release it descends from, says how far
// past it the commit is, and resolves back to that commit. `--always` matters
// more than it looks: most repositories in the fleet have never been tagged, and
// without it they would fail to publish rather than publish a SHA.
func gitDescribeVersion() (string, error) {
	out, err := exec.Command("git", "describe", "--tags", "--always").Output()
	if err != nil {
		return "", fmt.Errorf("git describe: %w", err)
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return "", fmt.Errorf("git describe produced no output")
	}
	return v, nil
}
```

Add `"os/exec"` to the import block in that file.

- [ ] **Step 5: Wire it into `resolveTeaReleaseInputs`**

In `cli/cmd/tea_release.go`, replace this existing block:

```go
	if in.Version == "" {
		return in, fmt.Errorf("--version is required: no release tag was found in the environment "+
			"(GITHUB_REF_TYPE was %q)", os.Getenv("GITHUB_REF_TYPE"))
	}
```

with:

```go
	// A branch push is not a release, but it still produced evidence worth
	// publishing. Derive a version for it rather than refusing, and say in the
	// object itself that it is not a release: `--pre-release` is forced here
	// because a caller cannot know in advance which of the two cases it is in.
	if in.Version == "" {
		if auto, _ := cmd.Flags().GetBool("auto-version"); auto {
			v, err := gitDescribeVersion()
			if err != nil {
				return in, fmt.Errorf("--auto-version: %w", err)
			}
			in.Version = v
			in.PreRelease = true
		}
	}
	if in.Version == "" {
		return in, fmt.Errorf("--version is required: no release tag was found in the environment "+
			"(GITHUB_REF_TYPE was %q)", os.Getenv("GITHUB_REF_TYPE"))
	}
```

Then replace the existing pre-release read:

```go
	in.PreRelease, _ = cmd.Flags().GetBool("pre-release")
```

with:

```go
	// Already true when --auto-version derived the version, so this ORs rather
	// than assigns: an explicit --pre-release adds to the decision, it does not
	// overwrite it.
	pre, _ := cmd.Flags().GetBool("pre-release")
	in.PreRelease = in.PreRelease || pre
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd /home/chris/GitHub/Vulnetix/cli && just fmt && go test ./cmd/ -run 'TeaRelease|GitDescribe' -v`
Expected: PASS, all seven tests.

- [ ] **Step 7: Run the full suite**

Run: `cd /home/chris/GitHub/Vulnetix/cli && just test`
Expected: PASS. `TestResolveTeaReleaseInputs_WithoutAutoVersionBranchStillErrors` is the guard that `cli/release.yml` is unaffected.

- [ ] **Step 8: Commit**

```bash
cd /home/chris/GitHub/Vulnetix/cli
git add cmd/tea_release.go cmd/tea_release_test.go
git commit -m "feat(tea): add --auto-version for non-tag release publishing

A branch push produces BOMs but has no tag, so tea release refused to run.
With --auto-version it derives the version from git describe and marks the
result a pre-release. Opt-in, so existing callers are unchanged."
```

---

### Task 2: GitHub release asset lookup

`--checksums-from-release` needs to find and download a release's checksums manifest. That is a GitHub REST concern, so it lives in `internal/github` alongside the existing artifact client.

**Files:**
- Create: `cli/internal/github/release.go`
- Test: `cli/internal/github/release_test.go` (create)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces, all in package `github`:
  - `type ReleaseAsset struct { Name string; BrowserDownloadURL string }`
  - `type Release struct { TagName string; Assets []ReleaseAsset }`
  - `func FetchReleaseByTag(ctx context.Context, token, apiURL, repository, tag string) (*Release, error)`
  - `func (r *Release) AssetMatching(substr string) *ReleaseAsset`
  - `func DownloadAsset(ctx context.Context, token string, a ReleaseAsset, destDir string) (string, error)`

  Task 3 calls `FetchReleaseByTag`, `AssetMatching` and `DownloadAsset`.

- [ ] **Step 1: Write the failing test**

Create `cli/internal/github/release_test.go`:

```go
package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetchReleaseByTag(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"tag_name": "v1.2.3",
			"assets": [
				{"name": "tool-linux-amd64", "browser_download_url": "https://example.com/tool-linux-amd64"},
				{"name": "checksums.txt", "browser_download_url": "https://example.com/checksums.txt"}
			]
		}`))
	}))
	defer srv.Close()

	rel, err := FetchReleaseByTag(context.Background(), "tok", srv.URL, "Vulnetix/cli", "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/repos/Vulnetix/cli/releases/tags/v1.2.3" {
		t.Errorf("path %q", gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("auth %q", gotAuth)
	}
	if rel.TagName != "v1.2.3" || len(rel.Assets) != 2 {
		t.Fatalf("release %+v", rel)
	}
}

// A missing release is not an error the caller should die on: a tag can exist
// without a GitHub release, and that release still has evidence worth
// publishing. It just has no download links.
func TestFetchReleaseByTag_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := FetchReleaseByTag(context.Background(), "tok", srv.URL, "Vulnetix/cli", "v9.9.9")
	if err == nil {
		t.Fatal("want an error for a release that does not exist")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should name the status: %v", err)
	}
}

// Projects spell it checksums.txt, SHA256SUMS, tool_checksums.txt. Matching a
// substring case-insensitively covers those without a per-repository input.
func TestAssetMatching(t *testing.T) {
	rel := &Release{Assets: []ReleaseAsset{
		{Name: "tool-linux-amd64"},
		{Name: "CHECKSUMS.txt"},
	}}
	got := rel.AssetMatching("checksums")
	if got == nil || got.Name != "CHECKSUMS.txt" {
		t.Fatalf("got %+v", got)
	}
	if rel.AssetMatching("sbom") != nil {
		t.Error("want nil when nothing matches")
	}
}

func TestDownloadAsset(t *testing.T) {
	const body = "b9f62ff7  tool-linux-amd64\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	dir := t.TempDir()
	path, err := DownloadAsset(context.Background(), "tok",
		ReleaseAsset{Name: "checksums.txt", BrowserDownloadURL: srv.URL}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != dir {
		t.Errorf("wrote outside the destination: %s", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != body {
		t.Errorf("content %q", b)
	}
}

// An asset name is attacker-influenced in the general case. It must not be able
// to escape the destination directory.
func TestDownloadAsset_RejectsPathTraversal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()

	_, err := DownloadAsset(context.Background(), "tok",
		ReleaseAsset{Name: "../escaped.txt", BrowserDownloadURL: srv.URL}, t.TempDir())
	if err == nil {
		t.Fatal("want an error for an asset name containing a path separator")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/chris/GitHub/Vulnetix/cli && go test ./internal/github/ -run 'Release|Asset' -v`
Expected: FAIL to compile, `undefined: FetchReleaseByTag`.

- [ ] **Step 3: Write the implementation**

Create `cli/internal/github/release.go`:

```go
package github

// Reading a GitHub release, for the one thing `tea release` needs from it: the
// checksums manifest the release already publishes. Taking the digests from
// that file rather than recomputing them is what makes the checksum a consumer
// reads through TEA the same string the project published.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// maxAssetBytes caps a manifest download. A checksums file is a few kilobytes;
// anything near this is not the file we asked for.
const maxAssetBytes = 8 << 20

type ReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type Release struct {
	TagName string         `json:"tag_name"`
	Assets  []ReleaseAsset `json:"assets"`
}

// FetchReleaseByTag reads one release by its tag.
//
// apiURL is a parameter rather than a constant because GitHub Enterprise serves
// a different host, and guessing github.com there would read the wrong instance.
func FetchReleaseByTag(ctx context.Context, token, apiURL, repository, tag string) (*Release, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/tags/%s",
		strings.TrimRight(apiURL, "/"), repository, tag)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %d %s", url, resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	var rel Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAssetBytes)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode release: %w", err)
	}
	return &rel, nil
}

// AssetMatching finds the first asset whose name contains substr, ignoring case.
//
// Substring rather than exact match because projects spell the same file
// checksums.txt, SHA256SUMS and tool_checksums.txt, and requiring each
// repository to declare which would be a per-repository input for a question
// the release itself already answers.
func (r *Release) AssetMatching(substr string) *ReleaseAsset {
	want := strings.ToLower(substr)
	for i := range r.Assets {
		if strings.Contains(strings.ToLower(r.Assets[i].Name), want) {
			return &r.Assets[i]
		}
	}
	return nil
}

// DownloadAsset writes an asset into destDir and returns its path.
func DownloadAsset(ctx context.Context, token string, a ReleaseAsset, destDir string) (string, error) {
	// The name comes from the API, so it is not ours. A name carrying a
	// separator would otherwise write outside destDir.
	if a.Name == "" || a.Name != filepath.Base(a.Name) || strings.ContainsAny(a.Name, `/\`) {
		return "", fmt.Errorf("refusing asset name %q: it is not a plain file name", a.Name)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.BrowserDownloadURL, nil)
	if err != nil {
		return "", err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %d %s", a.BrowserDownloadURL, resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	path := filepath.Join(destDir, a.Name)
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	if _, err := io.Copy(f, io.LimitReader(resp.Body, maxAssetBytes)); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/chris/GitHub/Vulnetix/cli && just fmt && go test ./internal/github/ -run 'Release|Asset' -v`
Expected: PASS, all five tests.

- [ ] **Step 5: Commit**

```bash
cd /home/chris/GitHub/Vulnetix/cli
git add internal/github/release.go internal/github/release_test.go
git commit -m "feat(github): read a release and download one of its assets

Needed so tea release can take digests from the checksums manifest a release
already publishes, rather than recomputing them into a second string that
could disagree with it."
```

---

### Task 3: `--checksums-from-release` on `tea release`

**Files:**
- Modify: `cli/cmd/tea_release.go` (`newTeaReleaseCommand`, `teaReleaseDistributions`)
- Test: `cli/cmd/tea_release_test.go` (append)

**Interfaces:**
- Consumes: `github.FetchReleaseByTag`, `(*github.Release).AssetMatching`, `github.DownloadAsset` from Task 2; the `--auto-version` flag registration site from Task 1.
- Produces: `resolveChecksumsManifest(cmd *cobra.Command) (string, error)` in package `cmd`. Task 4 calls the flag from YAML.

- [ ] **Step 1: Write the failing test**

Append to `cli/cmd/tea_release_test.go`:

```go
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
```

Add to that file's import block: `"net/http"`, `"net/http/httptest"`, `"os"`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/chris/GitHub/Vulnetix/cli && go test ./cmd/ -run 'ChecksumsManifest' -v`
Expected: FAIL to compile, `undefined: resolveChecksumsManifest`.

- [ ] **Step 3: Add the flag**

In `cli/cmd/tea_release.go`, inside `newTeaReleaseCommand`, immediately after the existing `cmd.Flags().String("checksums", ...)` call:

```go
	cmd.Flags().Bool("checksums-from-release", false,
		"on a tag run, take --checksums from the GitHub release's checksums asset")
```

- [ ] **Step 4: Write `resolveChecksumsManifest`**

Append to `cli/cmd/tea_release.go`:

```go
// resolveChecksumsManifest decides which checksums file, if any, to publish
// distributions from.
//
// Three ways it legitimately resolves to nothing, none of which is a failure:
// the flag is off, the run is not a tag run, or the release ships no such
// asset. A release with evidence and no download links is incomplete; a job
// that died trying to find one publishes nothing at all, which is worse.
func resolveChecksumsManifest(cmd *cobra.Command) (string, error) {
	if explicit, _ := cmd.Flags().GetString("checksums"); explicit != "" {
		return explicit, nil
	}
	if fromRelease, _ := cmd.Flags().GetBool("checksums-from-release"); !fromRelease {
		return "", nil
	}
	if !strings.EqualFold(os.Getenv("GITHUB_REF_TYPE"), "tag") {
		return "", nil
	}

	repository := strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY"))
	tag := strings.TrimSpace(os.Getenv("GITHUB_REF_NAME"))
	if repository == "" || tag == "" {
		return "", nil
	}
	apiURL := strings.TrimSpace(os.Getenv("GITHUB_API_URL"))
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}

	ctx, cancel := teaContext(cmd)
	defer cancel()

	rel, err := github.FetchReleaseByTag(ctx, os.Getenv("GITHUB_TOKEN"), apiURL, repository, tag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not read the GitHub release for %s: %v\n", tag, err)
		return "", nil
	}
	asset := rel.AssetMatching("checksums")
	if asset == nil {
		fmt.Fprintf(os.Stderr, "warning: release %s publishes no checksums asset; no distributions will be published\n", tag)
		return "", nil
	}

	dir, err := os.MkdirTemp("", "vulnetix-tea-")
	if err != nil {
		return "", err
	}
	path, err := github.DownloadAsset(ctx, os.Getenv("GITHUB_TOKEN"), *asset, dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not download %s: %v\n", asset.Name, err)
		return "", nil
	}
	return path, nil
}
```

Add `"github.com/vulnetix/cli/v3/internal/github"` to that file's import block.

- [ ] **Step 5: Use it in `teaReleaseDistributions`**

In `cli/cmd/tea_release.go`, replace the opening of `teaReleaseDistributions`:

```go
	if manifest, _ := cmd.Flags().GetString("checksums"); manifest != "" {
```

with:

```go
	manifest, err := resolveChecksumsManifest(cmd)
	if err != nil {
		return nil, err
	}
	if manifest != "" {
```

The body of that block is otherwise unchanged. Its existing `parsed, err := distributionsFromChecksums(...)` stays as it is: it is inside the `if` block, so it declares a new `parsed` and shadows the outer `err`, which compiles.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd /home/chris/GitHub/Vulnetix/cli && just fmt && go test ./cmd/ -run 'ChecksumsManifest|TeaRelease|GitDescribe' -v`
Expected: PASS.

- [ ] **Step 7: Run the full suite and lint**

Run: `cd /home/chris/GitHub/Vulnetix/cli && just test && just lint`
Expected: PASS.

- [ ] **Step 8: Confirm the dry run end to end**

Run:
```bash
cd /home/chris/GitHub/Vulnetix/cli
vulnetix sca --no-banner --no-progress -o /tmp/spot.cdx.json || true
go run . tea release /tmp/spot.cdx.json --dry-run --auto-version --product Vulnetix/cli
```
Expected: the printed `version` is a `git describe` string such as `v3.75.0-12-gabc1234`, and stderr says `dry run — nothing was published`.

- [ ] **Step 9: Commit**

```bash
cd /home/chris/GitHub/Vulnetix/cli
git add cmd/tea_release.go cmd/tea_release_test.go
git commit -m "feat(tea): add --checksums-from-release

Fills --checksums from the release's own checksums asset on a tag run, so a
shared workflow needs no per-repository configuration to publish download
links. Resolves to nothing on a branch run or a release without one, rather
than failing the publish."
```

---

### Task 4: Release the CLI, then write the reusable workflow

The workflow installs a published CLI, so the flags must exist in a release before any caller is wired.

**Files:**
- Create: `cli/.github/workflows/tea-release.yml`

**Interfaces:**
- Consumes: `--auto-version` (Task 1) and `--checksums-from-release` (Task 3).
- Produces: a `workflow_call` workflow at `Vulnetix/cli/.github/workflows/tea-release.yml@main` with inputs `visibility`, `channels`, `runs-on`, `cli-version`. Tasks 5, 6 and 7 call it.

- [ ] **Step 1: Cut a CLI release**

Push the commits from Tasks 1 to 3 and let `release.yml` run, or tag manually. Then record the released version:

```bash
cd /home/chris/GitHub/Vulnetix/cli
git push
gh release list --limit 3
```

Expected: a release exists whose binary has both flags. Verify:

```bash
curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --install-dir /tmp/vbin --version "$RELEASED"
/tmp/vbin/vulnetix tea release --help | grep -E 'auto-version|checksums-from-release'
```
Expected: both flags listed. Note `$RELEASED` for the next step.

- [ ] **Step 2: Write the workflow**

Create `cli/.github/workflows/tea-release.yml`, substituting the real released version for `v3.NN.0`:

```yaml
name: TEA Release

# Publishes a repository's transparency evidence to the Transparency Exchange
# API. Called from each repository's vulnetix.yml, which is where the SBOM,
# CBOM and AI-BOM are actually produced: a reusable workflow runs inside the
# calling repository's run, so it can download that run's artifacts, and
# GITHUB_REPOSITORY names the caller rather than this repository.
#
# There is deliberately no branching shell here. Tag versus branch, a
# repository with no tags, a release with no checksums asset: all of that is
# handled by --auto-version and --checksums-from-release, where it is covered
# by Go tests instead of only being exercised in production.

on:
  workflow_call:
    inputs:
      visibility:
        description: 'public, shared, or empty to leave the objects private'
        type: string
        default: ''
      channels:
        description: 'newline-separated --channel specs, one per line'
        type: string
        default: ''
      runs-on:
        description: 'runner label expression'
        type: string
        default: 'ubuntu-latest'
      cli-version:
        description: 'Vulnetix CLI version to install'
        type: string
        default: 'v3.NN.0'

# Pinned, not floating: a CLI regression on latest would otherwise stop
# publishing in every repository at once.

# tea release is idempotent on the identity it derives, but not safe against
# itself: two runs for one ref could race each other's collection publish.
# cancel-in-progress is false because a queued publish is still wanted, unlike
# a superseded deploy.
concurrency:
  group: tea-${{ github.repository }}-${{ github.ref }}
  cancel-in-progress: false

jobs:
  publish:
    name: Publish to TEA
    runs-on: ${{ inputs.runs-on }}
    timeout-minutes: 20
    permissions:
      contents: read   # checkout, and reading the GitHub release on a tag run
      actions: read    # download the calling run's artifacts
    env:
      VULNETIX_ORG_ID: ${{ secrets.VULNETIX_ORG_ID }}
      VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}
      GITHUB_TOKEN: ${{ github.token }}
    steps:
      # fetch-depth 0 because --auto-version runs `git describe`, and a shallow
      # checkout carries no tags to describe against.
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0

      - name: Install Vulnetix CLI
        run: |
          curl -fsSL https://cli.vulnetix.com/install.sh \
            | sh -s -- --install-dir "$HOME/.local/bin" --version "${{ inputs.cli-version }}"
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"

      # continue-on-error because `pattern` with no match is an error, and a
      # repository whose scans produced nothing should still publish its
      # release object rather than fail the job.
      - name: Download the BOMs this run produced
        continue-on-error: true
        uses: actions/download-artifact@v6
        with:
          pattern: '{sca,cbom,aibom}'
          merge-multiple: true
          path: boms

      - name: Report what was found
        run: |
          set -euo pipefail
          if ls boms/*.cdx.json >/dev/null 2>&1; then
            ls -l boms/*.cdx.json
          else
            echo "::warning::no BOM artifacts were found; publishing the release without evidence"
          fi

      - name: Publish product, release, artifacts and distributions
        run: |
          set -euo pipefail

          args=(tea release)
          for f in boms/*.cdx.json; do
            [ -e "$f" ] && args+=("$f")
          done
          args+=(--auto-version --checksums-from-release)

          if [ -n "${{ inputs.visibility }}" ]; then
            args+=(--visibility "${{ inputs.visibility }}")
          fi

          while IFS= read -r channel; do
            [ -n "$channel" ] && args+=(--channel "$channel")
          done <<< "${{ inputs.channels }}"

          vulnetix "${args[@]}"
```

- [ ] **Step 3: Verify the workflow parses**

Run: `cd /home/chris/GitHub/Vulnetix/cli && actionlint .github/workflows/tea-release.yml`
Expected: no output, exit 0.

- [ ] **Step 4: Commit**

```bash
cd /home/chris/GitHub/Vulnetix/cli
git add .github/workflows/tea-release.yml
git commit -m "ci: add reusable tea-release workflow

One workflow_call workflow every repository calls from its vulnetix.yml, so
changing how publishing works means editing one file rather than twenty-five."
git push
```

---

### Task 5: Pilot on `vdb-cyclonedx`

Public, low blast radius, produces real BOMs. One repository proves the wiring before the other twenty-four inherit any mistake in it.

**Files:**
- Modify: `~/GitHub/Vulnetix/vdb-cyclonedx/.github/workflows/vulnetix.yml`

**Interfaces:**
- Consumes: the reusable workflow from Task 4.
- Produces: the exact caller-job text that Tasks 6 and 7 replicate.

- [ ] **Step 1: Add the release trigger**

In `~/GitHub/Vulnetix/vdb-cyclonedx/.github/workflows/vulnetix.yml`, replace:

```yaml
on:
  push:
  workflow_dispatch:
```

with:

```yaml
on:
  push:
  # A release cut from a tag that already existed produces no push event, so
  # the tag-push trigger above does not cover it.
  release:
    types: [published]
  workflow_dispatch:
```

- [ ] **Step 2: Add the caller job**

Append to the end of the same file, at the same indentation as the existing `analyze` and `publish` jobs:

```yaml
  publish-tea:
    name: TEA
    needs: analyze
    # The transparency log being unreachable is not a reason to fail this
    # repository's CI. The publish records what was built; it does not gate it.
    continue-on-error: true
    uses: Vulnetix/cli/.github/workflows/tea-release.yml@main
    with:
      visibility: public
    secrets: inherit
```

- [ ] **Step 3: Verify it parses**

Run: `cd ~/GitHub/Vulnetix/vdb-cyclonedx && actionlint .github/workflows/vulnetix.yml`
Expected: no output, exit 0.

- [ ] **Step 4: Commit and push**

```bash
cd ~/GitHub/Vulnetix/vdb-cyclonedx
git add .github/workflows/vulnetix.yml
git commit -m "ci: publish transparency evidence to TEA on every push and release"
git push
```

- [ ] **Step 5: Watch the run**

Run: `cd ~/GitHub/Vulnetix/vdb-cyclonedx && gh run watch "$(gh run list --limit 1 --json databaseId --jq '.[0].databaseId')"`
Expected: the `TEA / Publish to TEA` job succeeds and its log prints `published N artifact(s) in collection v1`.

- [ ] **Step 6: Confirm the objects exist**

Take the product UUID from the job log, then:

```bash
vulnetix tea product "$PRODUCT_UUID"
```
Expected: the product lists a release whose version is a `git describe` string, marked `(pre-release)`.

- [ ] **Step 7: Verify a tag run**

```bash
cd ~/GitHub/Vulnetix/vdb-cyclonedx
git tag v0.0.1-teatest && git push origin v0.0.1-teatest
gh run watch "$(gh run list --limit 1 --json databaseId --jq '.[0].databaseId')"
vulnetix tea product "$PRODUCT_UUID"
```
Expected: a release `v0.0.1-teatest` appears **without** the `(pre-release)` marker. If `vdb-cyclonedx` publishes a GitHub release with a checksums asset, the job log also reports `published N distribution(s)`; if it does not, the log carries the `publishes no checksums asset` warning and still succeeds.

Then remove the test tag:

```bash
git push --delete origin v0.0.1-teatest && git tag -d v0.0.1-teatest
```

Note that deleting the tag does not unpublish the TEA release. That is expected and harmless.

---

### Task 6: Roll out to the remaining public repositories

Seven repositories, identical edit, `visibility: public`.

**Files, all `.github/workflows/vulnetix.yml` under `~/GitHub/Vulnetix/`:**
- Modify: `homebrew-tap`, `scoop-bucket`, `pix-ai-coding-assistant`, `ietf-crit-spec`, `transparency-exchange-api`, `malscan-engine`

(`cli` is public too but is handled separately in Task 7, and `vdb-cyclonedx` was Task 5.)

**Interfaces:**
- Consumes: the caller-job text proven in Task 5.
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Apply the same two edits to each repository**

For each of the six repositories, make exactly the changes from Task 5 Step 1 and Step 2, verbatim, including `visibility: public`.

- [ ] **Step 2: Verify every file parses**

```bash
cd ~/GitHub/Vulnetix
for r in homebrew-tap scoop-bucket pix-ai-coding-assistant ietf-crit-spec transparency-exchange-api malscan-engine; do
  echo "== $r"
  actionlint "$r/.github/workflows/vulnetix.yml"
done
```
Expected: no output under any repository name, exit 0 throughout.

- [ ] **Step 3: Commit and push each**

```bash
cd ~/GitHub/Vulnetix
for r in homebrew-tap scoop-bucket pix-ai-coding-assistant ietf-crit-spec transparency-exchange-api malscan-engine; do
  git -C "$r" add .github/workflows/vulnetix.yml
  git -C "$r" commit -m "ci: publish transparency evidence to TEA on every push and release"
  git -C "$r" push
done
```

- [ ] **Step 4: Confirm each run reached the publish job**

```bash
cd ~/GitHub/Vulnetix
for r in homebrew-tap scoop-bucket pix-ai-coding-assistant ietf-crit-spec transparency-exchange-api malscan-engine; do
  echo "== $r"
  gh -R "Vulnetix/$r" run list --limit 1
done
```
Expected: the most recent run for each is `completed` and `success`. Investigate any repository whose `TEA` job was skipped, which would mean `needs: analyze` did not resolve.

---

### Task 7: Roll out to the private repositories, and to `cli`

Seventeen private repositories pass no `visibility` input. `cli` is public but must not publish twice on a tag.

**Files, all `.github/workflows/vulnetix.yml` under `~/GitHub/Vulnetix/`:**
- Modify: `ai-firewall`, `github-runner-aws`, `mcp-server`, `osm-submitter`, `package-firewall`, `pkgregistry`, `s3-queue-gui`, `saas`, `vdb-api`, `vdb-api-cyclonedx-uploads`, `vdb-manager`, `vdb-sca-match`, `vdb-sca-monitor`, `vdb-site`, `vulnetix-authentic-aws`, `vulnetix-vscode`, `website`
- Modify: `cli/.github/workflows/vulnetix.yml`

**Interfaces:**
- Consumes: the reusable workflow from Task 4.
- Produces: nothing.

- [ ] **Step 1: Apply the trigger edit and the caller job to the seventeen private repositories**

Same edits as Task 5 Step 1 and Step 2, except the caller job carries **no** `with:` block at all:

```yaml
  publish-tea:
    name: TEA
    needs: analyze
    continue-on-error: true
    uses: Vulnetix/cli/.github/workflows/tea-release.yml@main
    secrets: inherit
```

Omitting `visibility` is what keeps these repositories' dependency inventories private. Do not add `visibility: private`; the flag takes `public` or `shared`, and passing anything else would be rejected by the server.

- [ ] **Step 2: Add the caller job to `cli`, gated against tag runs**

In `cli/.github/workflows/vulnetix.yml`, apply the trigger edit from Task 5 Step 1, then append:

```yaml
  publish-tea:
    name: TEA
    needs: analyze
    # Not on a tag. release.yml already publishes this repository's tagged
    # releases, and it waits for the Homebrew tap and Scoop bucket to carry the
    # version before advertising `brew install` for it. This job cannot
    # reproduce that ordering, so it stays out of the way on tags.
    if: github.ref_type != 'tag'
    continue-on-error: true
    uses: Vulnetix/cli/.github/workflows/tea-release.yml@main
    with:
      visibility: public
    secrets: inherit
```

- [ ] **Step 3: Verify every file parses**

```bash
cd ~/GitHub/Vulnetix
for r in ai-firewall github-runner-aws mcp-server osm-submitter package-firewall \
         pkgregistry s3-queue-gui saas vdb-api vdb-api-cyclonedx-uploads \
         vdb-manager vdb-sca-match vdb-sca-monitor vdb-site \
         vulnetix-authentic-aws vulnetix-vscode website cli; do
  echo "== $r"
  actionlint "$r/.github/workflows/vulnetix.yml"
done
```
Expected: no output under any repository name, exit 0 throughout.

- [ ] **Step 4: Confirm no private repository declares a visibility**

```bash
cd ~/GitHub/Vulnetix
for r in ai-firewall github-runner-aws mcp-server osm-submitter package-firewall \
         pkgregistry s3-queue-gui saas vdb-api vdb-api-cyclonedx-uploads \
         vdb-manager vdb-sca-match vdb-sca-monitor vdb-site \
         vulnetix-authentic-aws vulnetix-vscode website; do
  if grep -q 'visibility' "$r/.github/workflows/vulnetix.yml"; then
    echo "STOP: $r declares a visibility and must not"
  fi
done
```
Expected: no output. Any line printed here is an irreversible disclosure waiting to happen; fix it before pushing.

- [ ] **Step 5: Commit and push each**

```bash
cd ~/GitHub/Vulnetix
for r in ai-firewall github-runner-aws mcp-server osm-submitter package-firewall \
         pkgregistry s3-queue-gui saas vdb-api vdb-api-cyclonedx-uploads \
         vdb-manager vdb-sca-match vdb-sca-monitor vdb-site \
         vulnetix-authentic-aws vulnetix-vscode website cli; do
  git -C "$r" add .github/workflows/vulnetix.yml
  git -C "$r" commit -m "ci: publish transparency evidence to TEA on every push and release"
  git -C "$r" push
done
```

- [ ] **Step 6: Confirm every run reached the publish job**

```bash
cd ~/GitHub/Vulnetix
for r in ai-firewall github-runner-aws mcp-server osm-submitter package-firewall \
         pkgregistry s3-queue-gui saas vdb-api vdb-api-cyclonedx-uploads \
         vdb-manager vdb-sca-match vdb-sca-monitor vdb-site \
         vulnetix-authentic-aws vulnetix-vscode website cli; do
  printf '%-28s ' "$r"
  gh -R "Vulnetix/$r" run list --limit 1 --json conclusion,status --jq '.[0] | "\(.status) \(.conclusion)"'
done
```
Expected: `completed success` for each. A `TEA` job that failed leaves the run green because of `continue-on-error`, so also check:

```bash
for r in saas vdb-api website; do
  gh -R "Vulnetix/$r" run view "$(gh -R "Vulnetix/$r" run list --limit 1 --json databaseId --jq '.[0].databaseId')" \
    --json jobs --jq '.jobs[] | select(.name | contains("TEA")) | "\(.name) \(.conclusion)"'
done
```
Expected: `success` for the TEA job in each.

- [ ] **Step 7: Confirm private objects really are private**

```bash
vulnetix tea products --limit 100
```
Expected: the private repositories' products appear for the authenticated organisation. Then confirm one is not readable anonymously:

```bash
curl -fsS -o /dev/null -w '%{http_code}\n' \
  "https://api.vulnetix.com/tea/v1/product/$PRIVATE_PRODUCT_UUID"
```
Expected: `401` or `404`, not `200`. A `200` means a private repository's SBOM is world-readable and must be corrected before going further.

---

## Notes on rollback

Removing a caller job stops future publishing. It does not unpublish anything already sent. Nothing published without `--visibility` was ever readable outside the organisation, so the only irreversible step in this plan is `visibility: public` on the eight public repositories, which is deliberate.
