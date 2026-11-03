package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pfw "github.com/vulnetix/cli/v4/pkg/packagefirewall"
)

func TestAddonRequires(t *testing.T) {
	npm, _ := pfw.ByCommand("npm")
	aur, _ := pfw.ByCommand("aur")
	goEco, _ := pfw.ByCommand("go")
	const hint = "requires the Package Firewall add-on"
	enforcedMissing := addonStatus{Known: true, Enforced: true, Entitled: false}
	cases := []struct {
		name string
		eco  pfw.Ecosystem
		plan string
		st   addonStatus
		want string
	}{
		{"free aur, not entitled", aur, "COMMUNITY", enforcedMissing, ""},
		{"npm, enforced and not entitled", npm, "COMMUNITY", enforcedMissing, hint},
		{"go proxy, enforced and not entitled", goEco, "PRO", enforcedMissing, hint},
		{"add-on holder is told nothing", npm, "PRO", addonStatus{Known: true, Enforced: true, Entitled: true}, ""},
		{"gating off is told nothing", npm, "PRO", addonStatus{Known: true, Enforced: false, Entitled: false}, ""},
		{"offline or unknown prints nothing", npm, "PRO", addonStatus{}, ""},
		{"unknown state never prints even with a community plan", npm, "COMMUNITY", addonStatus{Known: false, Enforced: true}, ""},
		{"enterprise passes whatever the site said", npm, "ENTERPRISE", enforcedMissing, ""},
	}
	for _, c := range cases {
		if got := addonRequires(c.eco, c.plan, c.st); got != c.want {
			t.Errorf("%s: addonRequires = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestFetchAddonStatus(t *testing.T) {
	var gotAuth, gotPath string
	serve := func(status int, body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
	}
	ctx := context.Background()

	srv := serve(200, `{"enforced":true,"packageFirewall":{"entitled":false},"socIntelligence":{"entitled":true}}`)
	st := fetchAddonStatus(ctx, srv.URL+"/api/site/v1", "ApiKey org:key", time.Second)
	srv.Close()
	if !st.Known || !st.Enforced || st.Entitled {
		t.Errorf("not entitled: %+v", st)
	}
	if gotAuth != "ApiKey org:key" || gotPath != "/api/site/v1/billing/addons" {
		t.Errorf("auth=%q path=%q", gotAuth, gotPath)
	}

	srv = serve(200, `{"enforced":true,"packageFirewall":{"entitled":true,"source":"stripe"}}`)
	st = fetchAddonStatus(ctx, srv.URL+"/api/site/v1", "ApiKey org:key", time.Second)
	srv.Close()
	if !st.Known || !st.Entitled {
		t.Errorf("entitled: %+v", st)
	}

	for name, c := range map[string]struct {
		status int
		body   string
	}{
		"401":                    {401, `{"error":"unauthenticated"}`},
		"404 on an older site":   {404, `not found`},
		"500":                    {500, `boom`},
		"garbage":                {200, `<html>`},
		"no packageFirewall key": {200, `{"enforced":true}`},
	} {
		srv := serve(c.status, c.body)
		st := fetchAddonStatus(ctx, srv.URL+"/api/site/v1", "ApiKey org:key", time.Second)
		srv.Close()
		if st.Known {
			t.Errorf("%s: state must be unknown, got %+v", name, st)
		}
	}

	// Unreachable and slow servers are unknown, not an error and not a hint.
	if st := fetchAddonStatus(ctx, "http://127.0.0.1:1/api/site/v1", "ApiKey org:key", 200*time.Millisecond); st.Known {
		t.Errorf("unreachable: %+v", st)
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer slow.Close()
	start := time.Now()
	if st := fetchAddonStatus(ctx, slow.URL+"/api/site/v1", "ApiKey org:key", 150*time.Millisecond); st.Known || time.Since(start) > time.Second {
		t.Errorf("timeout: %+v after %v", st, time.Since(start))
	}
	if st := fetchAddonStatus(ctx, "http://example.invalid", "", time.Second); st.Known {
		t.Error("no credential: nothing to ask, unknown")
	}
}
