package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/tea"
)

// ── harness ─────────────────────────────────────────────────────────────────

// teaIsolate removes every way the developer's own credentials could reach a
// test: env vars, the home and project credential files, and netrc.
func teaIsolate(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"VULNETIX_API_TOKEN", "VULNETIX_API_KEY", "VULNETIX_ORG_ID",
		"VVD_ORG", "VVD_SECRET",
	} {
		t.Setenv(k, "")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv(auth.CredentialsDirEnv, t.TempDir())
	t.Chdir(t.TempDir())
}

type teaItemFixture struct {
	UUID        string           `json:"uuid"`
	Name        string           `json:"name"`
	Identifiers []tea.Identifier `json:"identifiers,omitempty"`
}

type teaRecorded struct {
	Path  string
	Query url.Values
	Auth  string
}

// teaFake is a TEA list endpoint over a fixed set of items. Its paging follows
// the real service's: pageSize 1..100 (default 25), an opaque "tea1:" token,
// and an exact idType/idValue filter.
type teaFake struct {
	mu       sync.Mutex
	items    []teaItemFixture
	requests []teaRecorded
	status   int // when non-zero, every request gets this status
	srv      *httptest.Server
}

func newTeaFake(t *testing.T, items []teaItemFixture) *teaFake {
	t.Helper()
	f := &teaFake{items: items}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *teaFake) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, teaRecorded{r.URL.Path, r.URL.Query(), r.Header.Get("Authorization")})
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if f.status != 0 {
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, `{"error":"UNAUTHORIZED"}`)
		return
	}
	q := r.URL.Query()
	pool := f.items
	if q.Get("idType") != "" {
		pool = nil
		for _, it := range f.items {
			for _, id := range it.Identifiers {
				if id.IDType == q.Get("idType") && id.IDValue == q.Get("idValue") {
					pool = append(pool, it)
					break
				}
			}
		}
	}
	size := 25
	if s := q.Get("pageSize"); s != "" {
		size, _ = strconv.Atoi(s)
	}
	start := 0
	if tok := q.Get("pageToken"); tok != "" {
		start, _ = strconv.Atoi(strings.TrimPrefix(tok, "tea1:"))
	}
	end := min(start+size, len(pool))
	page := map[string]any{"results": pool[min(start, len(pool)):end], "hasNext": end < len(pool)}
	if end < len(pool) {
		page["nextPageToken"] = fmt.Sprintf("tea1:%d", end)
	} else {
		page["nextPageToken"] = ""
	}
	_ = json.NewEncoder(w).Encode(page)
}

func (f *teaFake) last(t *testing.T) teaRecorded {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		t.Fatal("no request reached the server")
	}
	return f.requests[len(f.requests)-1]
}

func (f *teaFake) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// teaRedirect sends every tea request to the fake whatever URL it was built for,
// keeping the path, so the fixed first party and public roots can be asserted on
// without the network.
func teaRedirect(t *testing.T, f *teaFake) {
	t.Helper()
	target, _ := url.Parse(f.srv.URL)
	teaTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		r := req.Clone(req.Context())
		r.URL.Scheme, r.URL.Host, r.Host = target.Scheme, target.Host, target.Host
		return http.DefaultTransport.RoundTrip(r)
	})
	t.Cleanup(func() { teaTransport = nil })
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

// runTea executes the tea command with args and captures what it printed.
func runTea(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	os.Stdout, os.Stderr = outW, errW

	var outBuf, errBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(&outBuf, outR) }()
	go func() { defer wg.Done(); _, _ = io.Copy(&errBuf, errR) }()

	c := newTeaCommand()
	c.SetArgs(args)
	c.SetOut(io.Discard)
	c.SetErr(io.Discard)
	c.SilenceUsage, c.SilenceErrors = true, true
	err = c.Execute()

	_ = outW.Close()
	_ = errW.Close()
	wg.Wait()
	os.Stdout, os.Stderr = oldOut, oldErr
	return outBuf.String(), errBuf.String(), err
}

func teaNumbered(n int, name func(i int) string) []teaItemFixture {
	out := make([]teaItemFixture, n)
	for i := range out {
		out[i] = teaItemFixture{
			UUID: fmt.Sprintf("00000000-0000-0000-0000-%012d", i),
			Name: name(i),
			Identifiers: []tea.Identifier{
				{IDType: "PURL", IDValue: fmt.Sprintf("pkg:github/org/repo%d", i)},
				{IDType: "TEI", IDValue: fmt.Sprintf("urn:tei:uuid:vulnetix.com:%d", i)},
			},
		}
	}
	return out
}

func plainNames(i int) string { return fmt.Sprintf("project-%d", i) }

func communityHeader() string {
	return "ApiKey " + auth.CommunityOrgID + ":" + auth.CommunityAPIKey
}

// ── catalogue selection and credentials ─────────────────────────────────────

func TestTeaCatalogue_PublicUsesPublicRootAndCommunityCredential(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, teaNumbered(3, plainNames))
	teaRedirect(t, f)

	if _, _, err := runTea(t, "--catalogue", "public", "products"); err != nil {
		t.Fatal(err)
	}
	got := f.last(t)
	if got.Path != "/tea/public/v1/products" {
		t.Errorf("path = %q, want the public root", got.Path)
	}
	if got.Auth != communityHeader() {
		t.Errorf("Authorization = %q, want the community credential %q", got.Auth, communityHeader())
	}
}

func TestTeaCatalogue_StoredCredentialsBeatTheFallback(t *testing.T) {
	teaIsolate(t)
	t.Setenv("VULNETIX_ORG_ID", "org-mine")
	t.Setenv("VULNETIX_API_KEY", "key-mine")
	f := newTeaFake(t, teaNumbered(1, plainNames))
	teaRedirect(t, f)

	if _, _, err := runTea(t, "--catalogue", "public", "products"); err != nil {
		t.Fatal(err)
	}
	if got := f.last(t).Auth; got != "ApiKey org-mine:key-mine" {
		t.Errorf("Authorization = %q, want the stored credential", got)
	}
}

func TestTeaCatalogue_FirstPartyDefaultNeverGetsTheCommunityKey(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, teaNumbered(1, plainNames))
	teaRedirect(t, f)

	if _, _, err := runTea(t, "products"); err != nil {
		t.Fatal(err)
	}
	got := f.last(t)
	if got.Path != "/tea/v1/products" {
		t.Errorf("path = %q, want the first party root", got.Path)
	}
	if got.Auth != "" {
		t.Errorf("Authorization = %q, want none: the community key on the first party root returns a different catalogue", got.Auth)
	}

	// Naming the first party catalogue is the same as the default.
	if _, _, err := runTea(t, "--catalogue", "first-party", "products"); err != nil {
		t.Fatal(err)
	}
	if got := f.last(t); got.Path != "/tea/v1/products" || got.Auth != "" {
		t.Errorf("--catalogue first-party: %+v", got)
	}
}

func TestTeaCatalogue_CustomServerNeverGetsTheCommunityKey(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, teaNumbered(1, plainNames))

	if _, _, err := runTea(t, "--server", f.srv.URL+"/other/v1/", "products"); err != nil {
		t.Fatal(err)
	}
	got := f.last(t)
	if got.Path != "/other/v1/products" {
		t.Errorf("path = %q", got.Path)
	}
	if got.Auth != "" {
		t.Errorf("Authorization = %q, want none", got.Auth)
	}
}

func TestTeaCatalogue_ServerEqualToPublicRootCountsAsPublic(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, teaNumbered(1, plainNames))
	teaRedirect(t, f)

	if _, _, err := runTea(t, "--server", tea.PublicServer+"/", "products"); err != nil {
		t.Fatal(err)
	}
	got := f.last(t)
	if got.Path != "/tea/public/v1/products" || got.Auth != communityHeader() {
		t.Errorf("got %+v, want public path with community credential", got)
	}
}

func TestTeaCatalogue_ServerAndCatalogueTogetherAreRejected(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, nil)
	for _, args := range [][]string{
		{"--server", f.srv.URL, "--catalogue", "public", "products"},
		{"--server", f.srv.URL, "--catalogue", "first-party", "products"},
	} {
		_, _, err := runTea(t, args...)
		if err == nil || !strings.Contains(err.Error(), "either --server or --catalogue") {
			t.Errorf("%v: err = %v", args, err)
		}
	}
	if f.count() != 0 {
		t.Error("a request was sent despite the conflicting flags")
	}
}

func TestTeaCatalogue_UnknownValueListsTheValidOnes(t *testing.T) {
	teaIsolate(t)
	_, _, err := runTea(t, "--catalogue", "mirror", "products")
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{`"mirror"`, "first-party", "public"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

func TestTeaCatalogue_WritesRefusePublic(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, nil)
	teaRedirect(t, f)
	_, _, err := runTea(t, "--catalogue", "public", "publish", "list")
	if err == nil || !strings.Contains(err.Error(), "read only") {
		t.Errorf("err = %v, want a read only refusal", err)
	}
	if f.count() != 0 {
		t.Error("a request was sent")
	}
}

func TestTeaCatalogue_VerboseNamesTheCommunityCredentialOnStderrOnly(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, teaNumbered(1, plainNames))
	teaRedirect(t, f)

	prev := teaVerbose
	t.Cleanup(func() { teaVerbose = prev })

	teaVerbose = func() bool { return false }
	_, stderr, err := runTea(t, "--catalogue", "public", "products")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr, "community credential") {
		t.Errorf("stderr without --verbose: %q", stderr)
	}

	teaVerbose = func() bool { return true }
	stdout, stderr, err := runTea(t, "--catalogue", "public", "products")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "using the community credential") {
		t.Errorf("stderr = %q", stderr)
	}
	if strings.Contains(stdout, "community") {
		t.Errorf("stdout carries the note: %q", stdout)
	}
}

// ── 401 ─────────────────────────────────────────────────────────────────────

func TestTea401Messages(t *testing.T) {
	t.Run("public root, stored key rejected", func(t *testing.T) {
		teaIsolate(t)
		t.Setenv("VULNETIX_ORG_ID", "org-mine")
		t.Setenv("VULNETIX_API_KEY", "stale")
		f := newTeaFake(t, nil)
		f.status = http.StatusUnauthorized
		teaRedirect(t, f)
		_, _, err := runTea(t, "--catalogue", "public", "products")
		if err == nil || !strings.Contains(err.Error(), "rejected your API key") ||
			!strings.Contains(err.Error(), "vulnetix auth login") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("public root, community credential rejected", func(t *testing.T) {
		teaIsolate(t)
		f := newTeaFake(t, nil)
		f.status = http.StatusUnauthorized
		teaRedirect(t, f)
		_, _, err := runTea(t, "--catalogue", "public", "products")
		if err == nil || !strings.Contains(err.Error(), "community credential") ||
			!strings.Contains(err.Error(), "vulnetix auth login") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("another server needs credentials", func(t *testing.T) {
		teaIsolate(t)
		f := newTeaFake(t, nil)
		f.status = http.StatusUnauthorized
		_, _, err := runTea(t, "--server", f.srv.URL, "products")
		if err == nil || !strings.Contains(err.Error(), "requires credentials") {
			t.Errorf("err = %v", err)
		}
		if strings.Contains(err.Error(), "community") {
			t.Errorf("a custom server must not mention the community fallback: %v", err)
		}
	})
	t.Run("first party with a stale key", func(t *testing.T) {
		teaIsolate(t)
		t.Setenv("VULNETIX_ORG_ID", "org-mine")
		t.Setenv("VULNETIX_API_KEY", "stale")
		f := newTeaFake(t, nil)
		f.status = http.StatusUnauthorized
		teaRedirect(t, f)
		_, _, err := runTea(t, "products")
		if err == nil || !strings.Contains(err.Error(), "rejected your credentials") {
			t.Errorf("err = %v", err)
		}
	})
}

// ── query strings ───────────────────────────────────────────────────────────

func TestTeaProducts_QueryStrings(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want map[string]string // absent keys must be absent from the request
		not  []string
	}{
		{"defaults", nil, map[string]string{"pageSize": "50"}, []string{"idType", "idValue", "pageToken"}},
		{"limit", []string{"--limit", "5"}, map[string]string{"pageSize": "5"}, nil},
		{"purl", []string{"--purl", "pkg:github/prefix-dev/pixi"},
			map[string]string{"idType": "PURL", "idValue": "pkg:github/prefix-dev/pixi"}, nil},
		{"tei", []string{"--tei", "urn:tei:uuid:vulnetix.com:abc"},
			map[string]string{"idType": "TEI", "idValue": "urn:tei:uuid:vulnetix.com:abc"}, nil},
		{"raw pair", []string{"--id-type", "cpe", "--id-value", "cpe:2.3:a:x:y"},
			map[string]string{"idType": "CPE", "idValue": "cpe:2.3:a:x:y"}, nil},
		{"compliance document", []string{"--id-type", "COMPLIANCE_DOCUMENT", "--id-value", "doc-1"},
			map[string]string{"idType": "COMPLIANCE_DOCUMENT", "idValue": "doc-1"}, nil},
		{"page token", []string{"--page-token", "tea1:25", "--limit", "10"},
			map[string]string{"pageToken": "tea1:25", "pageSize": "10"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			teaIsolate(t)
			f := newTeaFake(t, teaNumbered(40, plainNames))
			args := append([]string{"--server", f.srv.URL, "products"}, c.args...)
			if _, _, err := runTea(t, args...); err != nil {
				t.Fatal(err)
			}
			got := f.last(t)
			if got.Path != "/products" {
				t.Errorf("path = %q", got.Path)
			}
			for k, v := range c.want {
				if got.Query.Get(k) != v {
					t.Errorf("%s = %q, want %q (query %v)", k, got.Query.Get(k), v, got.Query)
				}
			}
			for _, k := range c.not {
				if got.Query.Has(k) {
					t.Errorf("%s should not be sent: %v", k, got.Query)
				}
			}
		})
	}
}

func TestTeaProducts_ExactFilterFindsTheProduct(t *testing.T) {
	teaIsolate(t)
	items := teaNumbered(30, plainNames)
	f := newTeaFake(t, items)
	stdout, _, err := runTea(t, "--server", f.srv.URL, "products", "--purl", "pkg:github/org/repo7")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(stdout) != items[7].UUID+"  project-7" {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestTeaProducts_LimitAboveOnePageReadsSeveral(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, teaNumbered(300, plainNames))
	stdout, _, err := runTea(t, "--server", f.srv.URL, "products", "--limit", "150")
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Split(strings.TrimSpace(strings.SplitN(stdout, "\n\n", 2)[0]), "\n")); n != 150 {
		t.Errorf("printed %d rows, want 150", n)
	}
	if f.count() != 2 {
		t.Fatalf("requests = %d, want 2 (100 then 50)", f.count())
	}
	if got := f.requests[1].Query.Get("pageSize"); got != "50" {
		t.Errorf("second pageSize = %q, want the 50 remaining", got)
	}
}

func TestTeaProducts_TableEndsWithTheNextPageToken(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, teaNumbered(40, plainNames))
	stdout, _, err := runTea(t, "--server", f.srv.URL, "products", "--limit", "10")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	last := lines[len(lines)-1]
	if !strings.Contains(last, "--page-token tea1:10") {
		t.Errorf("last line = %q", last)
	}

	// The token continues where the page stopped.
	stdout, _, err = runTea(t, "--server", f.srv.URL, "products", "--limit", "10", "--page-token", "tea1:10")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "project-10") || strings.Contains(stdout, "project-9\n") {
		t.Errorf("continuation started in the wrong place: %q", stdout)
	}
}

func TestTeaProducts_LastPageHasNoTokenLine(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, teaNumbered(3, plainNames))
	stdout, _, err := runTea(t, "--server", f.srv.URL, "products")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout, "page-token") {
		t.Errorf("stdout = %q", stdout)
	}
}

// ── --all ───────────────────────────────────────────────────────────────────

func TestTeaProducts_AllFollowsTokens(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, teaNumbered(230, plainNames))
	stdout, stderr, err := runTea(t, "--server", f.srv.URL, "products", "--all")
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Split(strings.TrimSpace(stdout), "\n")); n != 230 {
		t.Errorf("printed %d rows, want all 230 (the default --limit must not apply to --all)", n)
	}
	if f.count() != 3 {
		t.Errorf("requests = %d, want 3", f.count())
	}
	if strings.Contains(stdout, "page-token") || stderr != "" {
		t.Errorf("an exhausted catalogue reports nothing: stdout tail / stderr = %q", stderr)
	}
}

func TestTeaProducts_AllStopsAtThePageCapAndSaysSo(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, teaNumbered(2500, plainNames))
	stdout, stderr, err := runTea(t, "--server", f.srv.URL, "products", "--all")
	if err != nil {
		t.Fatal(err)
	}
	if f.count() != 20 {
		t.Errorf("requests = %d, want the 20 page cap", f.count())
	}
	if n := len(strings.Split(strings.TrimSpace(stdout), "\n")); n != 2000 {
		t.Errorf("printed %d rows, want 2000", n)
	}
	if !strings.Contains(stderr, "stopped after 20 pages") || !strings.Contains(stderr, "--page-token tea1:2000") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestTeaProducts_AllWithExplicitLimitStillCaps(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, teaNumbered(500, plainNames))
	stdout, _, err := runTea(t, "--server", f.srv.URL, "products", "--all", "--limit", "120")
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Split(strings.TrimSpace(strings.SplitN(stdout, "\n\n", 2)[0]), "\n")); n != 120 {
		t.Errorf("printed %d rows, want 120", n)
	}
}

// ── --search ────────────────────────────────────────────────────────────────

func TestTeaProducts_SearchPagesAcrossFakePages(t *testing.T) {
	teaIsolate(t)
	items := teaNumbered(250, func(i int) string {
		switch i {
		case 5:
			return "Pixi"
		case 120:
			return "my-PIXI-tool"
		}
		return plainNames(i)
	})
	// A match that lives only in an identifier, on the third page.
	items[210].Identifiers = append(items[210].Identifiers, tea.Identifier{IDType: "PURL", IDValue: "pkg:github/prefix-dev/Pixi"})
	f := newTeaFake(t, items)

	stdout, stderr, err := runTea(t, "--server", f.srv.URL, "products", "--search", "pixi")
	if err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(rows) != 3 {
		t.Fatalf("rows = %q, want 3 matches (name, name, identifier)", rows)
	}
	if f.count() != 3 {
		t.Errorf("requests = %d, want 3 pages of 100", f.count())
	}
	for _, r := range f.requests {
		if r.Query.Get("pageSize") != "100" {
			t.Errorf("search must read 100 at a time, got %v", r.Query)
		}
	}
	if stderr != "" {
		t.Errorf("stderr = %q; a search that read the whole catalogue says nothing", stderr)
	}
}

func TestTeaProducts_SearchStopsAtTheCapAndSaysSo(t *testing.T) {
	teaIsolate(t)
	items := teaNumbered(2500, func(i int) string {
		if i == 2300 {
			return "needle"
		}
		return plainNames(i)
	})
	f := newTeaFake(t, items)

	stdout, stderr, err := runTea(t, "--server", f.srv.URL, "products", "--search", "needle")
	if err != nil {
		t.Fatal(err)
	}
	if f.count() != 20 {
		t.Errorf("requests = %d, want the 20 page cap", f.count())
	}
	if strings.TrimSpace(stdout) != "" && strings.Contains(stdout, "needle") {
		t.Errorf("the match beyond the cap should not be found: %q", stdout)
	}
	want := "searched the first 2000 items; use --purl or --tei for an exact match"
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
}

func TestTeaProducts_SearchNoMatchesSaysSo(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, teaNumbered(10, plainNames))
	stdout, stderr, err := runTea(t, "--server", f.srv.URL, "products", "--search", "absent")
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "" || !strings.Contains(stderr, "no products matched") {
		t.Errorf("stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestTeaProducts_SearchHonoursLimit(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, teaNumbered(300, plainNames))
	stdout, stderr, err := runTea(t, "--server", f.srv.URL, "products", "--search", "project", "--limit", "7")
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Split(strings.TrimSpace(stdout), "\n")); n != 7 {
		t.Errorf("printed %d rows, want 7", n)
	}
	if !strings.Contains(stderr, "--limit") {
		t.Errorf("stderr = %q", stderr)
	}
	if f.count() != 1 {
		t.Errorf("requests = %d; the limit was met on page one", f.count())
	}
}

// ── flag validation ─────────────────────────────────────────────────────────

func TestTeaProducts_FlagCombinationsAreRejected(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"purl and tei", []string{"--purl", "pkg:a", "--tei", "urn:b"}, "--purl and --tei cannot be combined"},
		{"purl and pair", []string{"--purl", "pkg:a", "--id-type", "CPE", "--id-value", "x"}, "--purl and --id-type/--id-value"},
		{"tei and pair", []string{"--tei", "urn:b", "--id-type", "CPE", "--id-value", "x"}, "--tei and --id-type/--id-value"},
		{"search and purl", []string{"--search", "x", "--purl", "pkg:a"}, "--search and --purl"},
		{"search and tei", []string{"--search", "x", "--tei", "urn:b"}, "--search and --tei"},
		{"search and pair", []string{"--search", "x", "--id-type", "CPE", "--id-value", "x"}, "--search and --id-type/--id-value"},
		{"id-type alone", []string{"--id-type", "PURL"}, "must be given together"},
		{"id-value alone", []string{"--id-value", "x"}, "must be given together"},
		{"bad id-type", []string{"--id-type", "ISBN", "--id-value", "x"}, "CPE, TEI, PURL, COMPLIANCE_DOCUMENT"},
		{"empty search", []string{"--search", " "}, "--search needs a value"},
		{"zero limit", []string{"--limit", "0"}, "--limit must be at least 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			teaIsolate(t)
			f := newTeaFake(t, nil)
			for _, noun := range []string{"products", "components"} {
				_, _, err := runTea(t, append([]string{"--server", f.srv.URL, noun}, c.args...)...)
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Errorf("%s: err = %v, want it to contain %q", noun, err, c.want)
				}
			}
			if f.count() != 0 {
				t.Error("a request was sent despite invalid flags")
			}
		})
	}
}

// ── output shape and components ─────────────────────────────────────────────

func TestTeaProducts_JSONShape(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, teaNumbered(40, plainNames))

	stdout, _, err := runTea(t, "--server", f.srv.URL, "products", "--limit", "10", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Results       []map[string]any `json:"results"`
		HasNext       *bool            `json:"hasNext"`
		NextPageToken *string          `json:"nextPageToken"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("not an object with results: %v\n%s", err, stdout)
	}
	if len(out.Results) != 10 || out.HasNext == nil || !*out.HasNext ||
		out.NextPageToken == nil || *out.NextPageToken != "tea1:10" {
		t.Errorf("got %s", stdout)
	}
	if strings.Contains(stdout, "page-token") {
		t.Error("JSON output must not carry the table's hint line")
	}

	// No match is an empty array, never null.
	stdout, _, err = runTea(t, "--server", f.srv.URL, "products", "--search", "absent", "--json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, `"results": []`) || !strings.Contains(stdout, `"hasNext": false`) {
		t.Errorf("stdout = %s", stdout)
	}
}

func TestTeaComponents_HitsTheComponentsEndpoint(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, teaNumbered(5, plainNames))
	teaRedirect(t, f)

	stdout, _, err := runTea(t, "--catalogue", "public", "components", "--purl", "pkg:github/org/repo2")
	if err != nil {
		t.Fatal(err)
	}
	got := f.last(t)
	if got.Path != "/tea/public/v1/components" {
		t.Errorf("path = %q", got.Path)
	}
	if got.Query.Get("idType") != "PURL" || got.Query.Get("idValue") != "pkg:github/org/repo2" {
		t.Errorf("query = %v", got.Query)
	}
	if !strings.HasSuffix(strings.TrimSpace(stdout), "  project-2") {
		t.Errorf("stdout = %q", stdout)
	}

	stdout, _, err = runTea(t, "--catalogue", "public", "components", "--search", "REPO3")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "project-3") {
		t.Errorf("identifier search over components: %q", stdout)
	}
}

// product and collection read through the selected root, not a fixed one.
func TestTeaProductAndCollection_UseTheSelectedRoot(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, nil)
	teaRedirect(t, f)

	// The fake answers every path with a list page; the decode may fail but the
	// request is what is being asserted.
	_, _, _ = runTea(t, "--catalogue", "public", "product", "abc")
	if f.count() != 2 {
		// A product read is two requests: the product, then its releases.
		t.Fatalf("product requests = %d", f.count())
	}
	if got := f.requests[0]; got.Path != "/tea/public/v1/product/abc" || got.Auth != communityHeader() {
		t.Errorf("product: %+v", got)
	}
	if got := f.requests[1]; got.Path != "/tea/public/v1/product/abc/releases" || got.Auth != communityHeader() {
		t.Errorf("releases: %+v", got)
	}
	_, _, _ = runTea(t, "--catalogue", "public", "collection", "rel-1")
	if got := f.last(t); got.Path != "/tea/public/v1/productRelease/rel-1/collection/latest" || got.Auth != communityHeader() {
		t.Errorf("collection: %+v", got)
	}
}

// distribution list is a read, so it follows --catalogue and gets the fallback.
func TestTeaDistributionList_UsesTheSelectedRoot(t *testing.T) {
	teaIsolate(t)
	f := newTeaFake(t, nil)
	teaRedirect(t, f)

	_, _, _ = runTea(t, "--catalogue", "public", "distribution", "list", "rel-2")
	if got := f.last(t); got.Path != "/tea/public/v1/componentRelease/rel-2" || got.Auth != communityHeader() {
		t.Errorf("distribution list: %+v", got)
	}
}
