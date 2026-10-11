package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	aifw "github.com/vulnetix/cli/v3/pkg/aifirewall"
	"github.com/vulnetix/cli/v3/pkg/kiroauth"
)

// fakeVault records the calls saveKiroLogin makes.
type fakeVault struct {
	mu      sync.Mutex
	entries []aifw.VaultEntry
	created *aifw.VaultSave
	patched string
	value   string
	auth    string
}

func (f *fakeVault) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/site/v1/vault", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.auth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{"entries": f.entries})
	})
	mux.HandleFunc("POST /api/site/v1/vault/entries", func(w http.ResponseWriter, r *http.Request) {
		var in aifw.VaultSave
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.created = &in
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"entry": aifw.VaultEntry{ID: "new", Name: in.Name, Version: 1, Last4: "abcd"}})
	})
	mux.HandleFunc("PATCH /api/site/v1/vault/entries/{id}", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.patched, f.value = r.PathValue("id"), in["value"]
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"entry": aifw.VaultEntry{ID: r.PathValue("id"), Version: 2}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

var kiroTestLogin = kiroauth.Login{RefreshToken: "rt", ClientID: "cid", ClientSecret: "cs", Region: "us-east-1"}

func TestSaveKiroLoginCreatesAFirewallEntry(t *testing.T) {
	f := &fakeVault{entries: []aifw.VaultEntry{
		{ID: "other", Kind: aifw.VaultKindProvider, Provider: "openai", State: "active", Grants: []aifw.VaultGrant{{Surface: aifw.VaultSurfaceFirewall, Effect: "allow", All: true}}},
		{ID: "pix-only", Kind: aifw.VaultKindProvider, Provider: aifw.KiroSlug, State: "active", Grants: []aifw.VaultGrant{{Surface: "pix_sandbox", Effect: "allow", All: true}}},
	}}
	srv := f.server(t)
	vc := aifw.VaultClient{BaseURL: srv.URL, Authorization: "ApiKey org:hmac"}
	e, created, err := saveKiroLogin(context.Background(), vc, kiroTestLogin, "kiro", []string{"  ABCDEF  "}, 30)
	if err != nil || !created || e.ID != "new" {
		t.Fatalf("%v %v %+v", err, created, e)
	}
	in := f.created
	if in == nil || in.Provider != aifw.KiroSlug || in.Kind != aifw.VaultKindProvider || in.Value != kiroTestLogin.Encode() {
		t.Fatalf("created %+v", in)
	}
	g := in.Grants[0]
	if g.Surface != aifw.VaultSurfaceFirewall || g.All || len(g.IDs) != 1 || g.IDs[0] != "abcdef" || in.ExpiresAt == 0 {
		t.Fatalf("grant %+v expires %d", g, in.ExpiresAt)
	}
	if f.auth != "ApiKey org:hmac" {
		t.Fatalf("Authorization = %q", f.auth)
	}
}

func TestSaveKiroLoginReplacesTheFirewallEntry(t *testing.T) {
	f := &fakeVault{entries: []aifw.VaultEntry{
		{ID: "revoked", Kind: aifw.VaultKindProvider, Provider: aifw.KiroSlug, State: "revoked", Grants: []aifw.VaultGrant{{Surface: aifw.VaultSurfaceFirewall, Effect: "allow", All: true}}},
		{ID: "live", Kind: aifw.VaultKindProvider, Provider: aifw.KiroSlug, State: "active", Grants: []aifw.VaultGrant{{Surface: aifw.VaultSurfaceFirewall, Effect: "allow", All: true}}},
	}}
	srv := f.server(t)
	vc := aifw.VaultClient{BaseURL: srv.URL, Authorization: "ApiKey org:hmac"}
	_, created, err := saveKiroLogin(context.Background(), vc, kiroTestLogin, "kiro", nil, 0)
	if err != nil || created {
		t.Fatalf("%v created=%v", err, created)
	}
	if f.patched != "live" || f.value != kiroTestLogin.Encode() || f.created != nil {
		t.Fatalf("patched %q created %+v", f.patched, f.created)
	}
}

func TestVaultClientReportsRefusals(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"only an owner or admin can change the vault"}`))
	}))
	defer srv.Close()
	_, err := aifw.VaultClient{BaseURL: srv.URL, Authorization: "ApiKey a:b"}.Entries(context.Background())
	if err == nil || !strings.Contains(err.Error(), "only an owner or admin") {
		t.Fatalf("err = %v", err)
	}
}
