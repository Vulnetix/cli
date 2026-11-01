package vdb

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulnetix/cli/v3/pkg/auth"
)

func TestOIDCHeaderOnCliRoutesOnly(t *testing.T) {
	seen := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.URL.Path] = r.Header.Get(GHAOIDCHeader)
		_, _ = w.Write([]byte(`{"meta":{},"data":{}}`))
	}))
	defer srv.Close()

	prev := GHAOIDCToken
	GHAOIDCToken = func() string { return "oidc-jwt" }
	t.Cleanup(func() { GHAOIDCToken = prev })

	c := &Client{BaseURL: srv.URL, APIVersion: "/v2", HTTPClient: srv.Client(), AuthMethod: auth.Token, Token: "t"}
	if _, err := c.CliFinalize(CliEnv{}, CliFinalizeRequest{IngestionSnapshotUuid: "s"}); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if _, err := c.CliVexIngest(t.Context(), CliEnv{}, CliVexIngestRequest{Origin: VexOriginUpload}); err != nil {
		t.Fatalf("vex-ingest: %v", err)
	}
	if _, err := c.DoRequest("GET", "/vuln/CVE-2024-1", nil); err != nil {
		t.Fatalf("vuln: %v", err)
	}

	for _, p := range []string{"/v2/cli.finalize", "/v2/cli.vex-ingest"} {
		if seen[p] != "oidc-jwt" {
			t.Errorf("%s: %s = %q, want the token", p, GHAOIDCHeader, seen[p])
		}
	}
	if v, ok := seen["/v2/vuln/CVE-2024-1"]; !ok || v != "" {
		t.Errorf("non-cli route carried %s = %q (seen=%v)", GHAOIDCHeader, v, ok)
	}
}

func TestNoOIDCHeaderWithoutToken(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Values(GHAOIDCHeader)
		_, _ = w.Write([]byte(`{"meta":{},"data":{}}`))
	}))
	defer srv.Close()

	prev := GHAOIDCToken
	GHAOIDCToken = func() string { return "" }
	t.Cleanup(func() { GHAOIDCToken = prev })

	c := &Client{BaseURL: srv.URL, APIVersion: "/v2", HTTPClient: srv.Client(), AuthMethod: auth.Token, Token: "t"}
	if _, err := c.CliFinalize(CliEnv{}, CliFinalizeRequest{IngestionSnapshotUuid: "s"}); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("header sent with no token: %v", got)
	}
}
