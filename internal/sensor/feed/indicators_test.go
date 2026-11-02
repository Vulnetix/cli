package feed

import (
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

const listBody = "# vulnetix indicators v1\n# feed catalog:phishing-army\n# etag abc123\nd evil.example\ni 203.0.113.9\n"

// indicatorSite serves one list at the catalog path, honouring ?etag=, and
// answers status when it is set.
type indicatorSite struct {
	status  atomic.Int32
	revoked atomic.Bool
	auth    atomic.Value
	paths   atomic.Value
}

func (s *indicatorSite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.auth.Store(r.Header.Get("Authorization"))
	s.paths.Store(r.URL.Path)
	if st := s.status.Load(); st != 0 {
		if st == http.StatusUnauthorized && s.revoked.Load() {
			w.WriteHeader(int(st))
			_, _ = w.Write([]byte(`{"error":"revoked","revoked":true}`))

			return
		}
		w.WriteHeader(int(st))

		return
	}
	if r.URL.Path != "/v1/runtime/feeds/catalog/phishing-army/indicators" && r.URL.Path != "/v1/runtime/feeds/org/"+orgFeed+"/indicators" {
		http.NotFound(w, r)

		return
	}
	if r.URL.Query().Get("etag") == "abc123" {
		w.WriteHeader(http.StatusNotModified)

		return
	}
	w.Header().Set("ETag", `"abc123"`)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		_, _ = zw.Write([]byte(listBody))
		_ = zw.Close()

		return
	}
	_, _ = w.Write([]byte(listBody))
}

const orgFeed = "6f1c7a3e-2b4d-4e8f-9a0b-1c2d3e4f5a6b"

func newIndicators(t *testing.T, ref string) (*Indicators, *indicatorSite) {
	t.Helper()
	site := &indicatorSite{}
	srv := httptest.NewServer(site)
	t.Cleanup(srv.Close)

	return &Indicators{Reference: ref, Endpoint: srv.URL + "/", Authorization: func() string { return "Sensor dev:secret" }}, site
}

func TestIndicatorsFetchLoadsOneUnverifiedRule(t *testing.T) {
	src, site := newIndicators(t, "catalog:phishing-army")
	got, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if site.auth.Load() != "Sensor dev:secret" {
		t.Fatalf("Authorization = %v", site.auth.Load())
	}
	if got.Verified || got.Unverified != UnverifiedIndicators || got.ETag != "abc123" || len(got.Rules) != 1 {
		t.Fatalf("loaded = %+v", got)
	}
	r := got.Rules[0]
	want := uuid.NewSHA1(uuid.NameSpaceURL, []byte("vulnetix-feed:catalog:phishing-army")).String()
	if r.RuleTable != "ioc" || r.RuleUUID != want || r.RuleType != "IOC_LIST" || r.Name != "catalog:phishing-army" || r.DeployMode != "log" || r.Body != listBody {
		t.Fatalf("rule = %+v", r)
	}

	// The second poll sends ?etag= and gets a 304.
	if _, err := src.Fetch(context.Background()); !errors.Is(err, ErrNotModified) {
		t.Fatalf("second fetch err = %v, want ErrNotModified", err)
	}
}

func TestIndicatorsOrgPath(t *testing.T) {
	src, site := newIndicators(t, "org:"+orgFeed)
	if _, err := src.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p := site.paths.Load(); p != "/v1/runtime/feeds/org/"+orgFeed+"/indicators" {
		t.Fatalf("path = %v", p)
	}
}

func TestIndicatorsRevokedAndErrors(t *testing.T) {
	src, site := newIndicators(t, "catalog:phishing-army")
	if _, err := src.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}

	site.status.Store(http.StatusInternalServerError)
	if _, err := src.Fetch(context.Background()); err == nil || errors.Is(err, ErrNotModified) {
		t.Fatalf("500 err = %v", err)
	}
	if src.etag != "abc123" {
		t.Fatalf("a failed fetch must keep the last etag, got %q", src.etag)
	}

	site.status.Store(http.StatusUnauthorized)
	if _, err := src.Fetch(context.Background()); err == nil || errors.Is(err, ErrRevoked) {
		t.Fatalf("plain 401 must not read as revoked: %v", err)
	}

	site.revoked.Store(true)
	if _, err := src.Fetch(context.Background()); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked err = %v", err)
	}
	site.status.Store(0)
	if _, err := src.Fetch(context.Background()); !errors.Is(err, ErrRevoked) {
		t.Fatalf("a revoked source stays revoked, err = %v", err)
	}
}

func TestIndicatorsTooLarge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := []byte(strings.Repeat("d a.example\n", 1<<16))
		for written := 0; written <= maxIndicators; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	src := &Indicators{Reference: "catalog:big", Endpoint: srv.URL}
	if _, err := src.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v", err)
	}
}

func TestIsIndicatorRef(t *testing.T) {
	for ref, want := range map[string]bool{
		"catalog:phishing-army":          true,
		"org:" + orgFeed:                 true,
		"org:not-a-uuid":                 false,
		"catalog:":                       false,
		"catalog:a/b":                    false,
		"https://vulnetix.com/feeds/a/b": false,
		"stix:foo":                       false,
	} {
		if got := IsIndicatorRef(ref); got != want {
			t.Errorf("IsIndicatorRef(%q) = %v, want %v", ref, got, want)
		}
	}
}
