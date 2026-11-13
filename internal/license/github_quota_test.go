package license

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// fakeGitHub is the GitHub API for the licence lookups: repos maps
// "owner/repo" to how that repository answers, and every response carries the
// quota as GitHub's headers do, one request less each time.
type fakeGitHub struct {
	t         *testing.T
	repos     map[string]fakeRepo
	limit     int
	remaining atomic.Int64
	// rateLimited answers every lookup with GitHub's primary rate-limit 403.
	rateLimited bool

	mu       sync.Mutex
	requests []string // lookups, not /rate_limit
}

type fakeRepo struct {
	spdx    string            // license.spdx_id on the repository; "" is null
	license string            // the text /license serves; "" is a 404
	files   map[string]string // root files and their text
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "token test-token" {
		f.t.Errorf("%s sent without the lookup token", r.URL.Path)
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "rate_limit" {
		_ = json.NewEncoder(w).Encode(map[string]any{"resources": map[string]any{
			"core": map[string]int{"limit": f.limit, "remaining": int(f.remaining.Load())}}})
		return
	}
	f.mu.Lock()
	f.requests = append(f.requests, path)
	f.mu.Unlock()
	left := f.remaining.Add(-1)
	if f.rateLimited {
		left = 0
	}
	w.Header().Set("X-RateLimit-Limit", fmt.Sprint(f.limit))
	w.Header().Set("X-RateLimit-Remaining", fmt.Sprint(left))
	if f.rateLimited {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded for installation ID 1."}`))
		return
	}

	parts := strings.SplitN(strings.TrimPrefix(path, "repos/"), "/", 3)
	repo, ok := f.repos[parts[0]+"/"+parts[1]]
	if !ok {
		http.NotFound(w, r)
		return
	}
	content := func(text string) map[string]any {
		return map[string]any{"content": base64.StdEncoding.EncodeToString([]byte(text))}
	}
	switch {
	case len(parts) == 2:
		var lic any
		if repo.spdx != "" {
			lic = map[string]string{"spdx_id": repo.spdx}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"license": lic})
	case parts[2] == "license" && repo.license != "":
		body := content(repo.license)
		body["license"] = map[string]string{"spdx_id": "NOASSERTION"}
		_ = json.NewEncoder(w).Encode(body)
	case parts[2] == "contents/":
		list := []map[string]string{}
		for name := range repo.files {
			list = append(list, map[string]string{"name": name})
		}
		_ = json.NewEncoder(w).Encode(list)
	case strings.HasPrefix(parts[2], "contents/"):
		text, ok := repo.files[strings.TrimPrefix(parts[2], "contents/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(content(text))
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeGitHub) lookups() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

// withFakeGitHub points the lookups at f with a token and no gh, as a runner
// without gh would, and a fresh budget, store and notice writer.
func withFakeGitHub(t *testing.T, f *fakeGitHub, actions bool) *bytes.Buffer {
	t.Helper()
	f.t = t
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)

	oldBase, oldStore, oldOut := ghAPIBase, licenseStoreDir, noticeOut
	ghAPIBase = srv.URL + "/"
	licenseStoreDir = t.TempDir()
	notices := &bytes.Buffer{}
	noticeOut = notices
	t.Cleanup(func() { ghAPIBase, licenseStoreDir, noticeOut = oldBase, oldStore, oldOut })

	t.Setenv("PATH", t.TempDir()) // no gh
	t.Setenv("GITHUB_TOKEN", "test-token")
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_ACTIONS", map[bool]string{true: "true", false: ""}[actions])
	resetLookupState()
	t.Cleanup(resetLookupState)
	return notices
}

func resetLookupState() {
	ghCLIOnce = sync.Once{}
	ghTokenOnce = sync.Once{}
	ghToken = ""
	ghIndefinite = sync.Map{}
	resetGitHubBudget()
}

func unknown(names ...string) []PackageLicense {
	var out []PackageLicense
	for _, n := range names {
		out = append(out, PackageLicense{PackageName: n, Ecosystem: "github-actions", LicenseSpdxID: "UNKNOWN"})
	}
	return out
}

const mitLicenseText = `MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.`

// A scan of this repository asked GitHub about 46 names that cannot be
// repositories ($/sbom from `uses: $/sbom`, a glob, "<your" from a template),
// each through the whole chain, in every job of the run.
func TestNamesThatCannotBeRepositoriesNeverReachGitHub(t *testing.T) {
	f := &fakeGitHub{limit: 5000}
	f.remaining.Store(5000)
	withFakeGitHub(t, f, false)

	pkgs := unknown("$/sbom", "**/*.{css,scss,less}", "<your", "-bad/repo", "owner/..")
	BatchFetchGitHubLicenses(pkgs, nil)
	if got := f.lookups(); len(got) != 0 {
		t.Fatalf("asked GitHub about names that are not repositories: %v", got)
	}
}

// What each shape of repository costs. The chain used to spend about 26
// requests on a repository GitHub cannot see (14 through gh, then the same
// again with GITHUB_TOKEN as a "PAT fallback"), and 14 on one with an
// unrecognised licence.
func TestLookupChainCost(t *testing.T) {
	f := &fakeGitHub{limit: 5000, repos: map[string]fakeRepo{
		"named/mit":       {spdx: "MIT"},
		"detected/text":   {license: mitLicenseText},
		"listing/only":    {files: map[string]string{"README": "hi", "COPYING": mitLicenseText}},
		"nothing/at-all":  {},
		"listing/ordered": {files: map[string]string{"LICENSE-THIRD-PARTY": "not a licence", "LICENSE": mitLicenseText}},
	}}
	f.remaining.Store(5000)
	withFakeGitHub(t, f, false)

	cases := []struct {
		repo     string
		want     string
		requests int
	}{
		{"named/mit", "MIT", 1},
		{"detected/text", "MIT", 3},   // repo, /license, its content
		{"listing/only", "MIT", 4},    // repo, /license 404, listing, COPYING
		{"nothing/at-all", "", 3},     // repo, /license 404, empty listing
		{"gone/away", "", 1},          // a 404 on the repository ends it
		{"listing/ordered", "MIT", 4}, // LICENSE before LICENSE-THIRD-PARTY
	}
	for _, c := range cases {
		before := len(f.lookups())
		lic, definitive := resolveRepoLicenseChecked(strings.Split(c.repo, "/")[0], strings.Split(c.repo, "/")[1])
		if lic != c.want {
			t.Errorf("%s: licence %q, want %q", c.repo, lic, c.want)
		}
		if got := len(f.lookups()) - before; got != c.requests {
			t.Errorf("%s: %d requests, want %d: %v", c.repo, got, c.requests, f.lookups()[before:])
		}
		if c.want == "" && !definitive {
			t.Errorf("%s: every request answered or said 404, so the miss is definitive", c.repo)
		}
	}
}

// Inside GitHub Actions the job token's quota belongs to the repository, so
// the lookups stop at ciLicenseShare of the limit and leave the rest to the
// forge pass, CodeQL and the release; what they did not check they declare.
func TestLookupsKeepTheirShareInGitHubActions(t *testing.T) {
	f := &fakeGitHub{limit: 5000, repos: map[string]fakeRepo{}}
	var names []string
	for i := range 40 {
		name := fmt.Sprintf("o/r%d", i)
		f.repos[name] = fakeRepo{spdx: "MIT"}
		names = append(names, name)
	}
	f.remaining.Store(4010) // ten requests above the 4,000 floor
	notices := withFakeGitHub(t, f, true)

	pkgs := unknown(names...)
	BatchFetchGitHubLicenses(pkgs, nil)

	got := len(f.lookups())
	// Eight lookups run at once, so up to seven more can be in flight when one
	// response shows the floor.
	if got < 10 || got > 10+7 {
		t.Fatalf("made %d requests; the budget should stop at the floor (10 requests away)", got)
	}
	resolved := 0
	for _, p := range pkgs {
		if p.LicenseSpdxID == "MIT" {
			resolved++
		}
	}
	if resolved != got {
		t.Errorf("%d requests resolved %d licences", got, resolved)
	}
	out := notices.String()
	if !strings.Contains(out, fmt.Sprintf("GitHub licence lookups: %d requests for 40 repositories", got)) {
		t.Errorf("no usage line for the job's log:\n%s", out)
	}
	if !strings.Contains(out, fmt.Sprintf("%d of 40 repositories not checked", 40-got)) ||
		!strings.Contains(out, "requests left") {
		t.Errorf("the repositories left unchecked were not declared:\n%s", out)
	}
}

// A run that starts with the quota already below the floor spends nothing:
// /rate_limit, which does not count against it, says so first.
func TestLookupsSpendNothingBelowTheFloor(t *testing.T) {
	f := &fakeGitHub{limit: 5000, repos: map[string]fakeRepo{"a/b": {spdx: "MIT"}}}
	f.remaining.Store(3000)
	notices := withFakeGitHub(t, f, true)

	BatchFetchGitHubLicenses(unknown("a/b", "c/d"), nil)
	if got := f.lookups(); len(got) != 0 {
		t.Fatalf("spent %d requests below the floor: %v", len(got), got)
	}
	if !strings.Contains(notices.String(), "2 of 2 repositories not checked") {
		t.Errorf("notice: %q", notices.String())
	}
}

// GitHub answering with its rate limit stops every lookup after it, and a miss
// it caused is never stored as the repository having no licence.
func TestRateLimitAnswerStopsLookups(t *testing.T) {
	f := &fakeGitHub{limit: 5000, rateLimited: true, repos: map[string]fakeRepo{}}
	var names []string
	for i := range 30 {
		names = append(names, fmt.Sprintf("o/r%d", i))
	}
	f.remaining.Store(5000)
	notices := withFakeGitHub(t, f, false)

	BatchFetchGitHubLicenses(unknown(names...), nil)
	if got := len(f.lookups()); got > 8 {
		t.Fatalf("kept asking after GitHub said the quota was spent: %d requests", got)
	}
	if !strings.Contains(notices.String(), "repositories not checked") {
		t.Errorf("notice: %q", notices.String())
	}
	if loadStoredMiss("github", "o/r0") {
		t.Error("a rate-limited lookup was stored as a definitive miss")
	}
}
