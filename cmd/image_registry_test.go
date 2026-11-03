package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vulnetix/cli/v4/internal/imagesrc"
	"github.com/vulnetix/cli/v4/pkg/auth"
)

// useSite points the site API at a test server for one test.
func useSite(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	t.Setenv("VULNETIX_WEB_URL", srv.URL)
}

func withCreds(t *testing.T, c *auth.Credentials, community bool) {
	t.Helper()
	pc, pm := vdbCreds, vdbCommunityMode
	t.Cleanup(func() { vdbCreds, vdbCommunityMode = pc, pm })
	vdbCreds, vdbCommunityMode = c, community
}

func apiKeyCreds() *auth.Credentials {
	return &auth.Credentials{OrgID: "org-1", APIKey: "abcdef", Method: auth.DirectAPIKey}
}

func TestImageTenantTokensOnlyForASignedInUploadingRun(t *testing.T) {
	withCreds(t, apiKeyCreds(), false)
	if imageTenantTokens(false) == nil {
		t.Fatal("a signed in run asks")
	}
	if imageTenantTokens(true) != nil {
		t.Fatal("--no-upload sends nothing to Vulnetix, so it does not ask")
	}
	withCreds(t, apiKeyCreds(), true)
	if imageTenantTokens(false) != nil {
		t.Fatal("a community run has no organisation to ask for")
	}
	withCreds(t, nil, false)
	if imageTenantTokens(false) != nil {
		t.Fatal("no credentials, no ask")
	}
	withCreds(t, &auth.Credentials{Method: auth.AuthMethod("none")}, false)
	if imageTenantTokens(false) != nil {
		t.Fatal("a credential that cannot authenticate to the site does not ask")
	}
}

func TestSiteOCITokensAsksForOneRepositoryWithTheUsersCredential(t *testing.T) {
	withCreds(t, apiKeyCreds(), false)
	var gotAuth, gotPath, gotMethod string
	var body map[string]string
	useSite(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath, gotMethod = r.Header.Get("Authorization"), r.URL.Path, r.Method
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "reg-token", "expiresAt": time.Now().Add(5 * time.Minute).UnixMilli(), "scheme": "bearer"})
	})
	tok, err := imageTenantTokens(false).OCIToken(context.Background(), "registry.acme.example:5000", "acme/api")
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/site/v1/scan-registries/oci-token" || gotAuth != "ApiKey org-1:abcdef" {
		t.Fatalf("%s %s %q", gotMethod, gotPath, gotAuth)
	}
	if body["registry"] != "registry.acme.example:5000" || body["repository"] != "acme/api" || len(body) != 2 {
		t.Fatalf("body = %v", body)
	}
	if tok.Token != "reg-token" || time.Until(tok.ExpiresAt) < 4*time.Minute {
		t.Fatalf("token = %+v", tok)
	}
}

func TestSiteOCITokensMapsTheAnswers(t *testing.T) {
	withCreds(t, apiKeyCreds(), false)
	answer := func(status int, body string) {
		useSite(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		})
	}
	ask := func() (*imagesrc.TenantToken, error) {
		return imageTenantTokens(false).OCIToken(context.Background(), "r.example", "a/b")
	}
	for name, c := range map[string]struct {
		status int
		body   string
		want   error
	}{
		"not connected":     {403, `{"code":"no_connection","error":"no registry connection serves this"}`, imagesrc.ErrNoConnection},
		"plan":              {403, `{"code":"plan_locked","planLocked":true,"error":"registry credentials are not in this plan"}`, imagesrc.ErrNoConnection},
		"not a member":      {403, `{"code":"forbidden","error":"only a member"}`, imagesrc.ErrNoConnection},
		"not authenticated": {401, `{"error":"not authenticated"}`, imagesrc.ErrNoConnection},
		"no token service":  {409, `{"code":"no_ephemeral_credential","error":"this registry has no token service"}`, imagesrc.ErrNoEphemeral},
	} {
		answer(c.status, c.body)
		if _, err := ask(); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	// Anything else is an error that names the status and the API's message.
	answer(502, `{"code":"registry_refused","error":"the registry did not issue a token for this repository"}`)
	if _, err := ask(); err == nil || !strings.Contains(err.Error(), "502") || !strings.Contains(err.Error(), "registry_refused") ||
		errors.Is(err, imagesrc.ErrNoConnection) || errors.Is(err, imagesrc.ErrNoEphemeral) {
		t.Errorf("502 = %v", err)
	}
	answer(200, `{"scheme":"bearer"}`)
	if _, err := ask(); err == nil {
		t.Error("an answer with no token is an error")
	}
	// No expiry from the server is a minute, not forever.
	answer(200, `{"token":"t"}`)
	if tok, err := ask(); err != nil || time.Until(tok.ExpiresAt) > 90*time.Second || time.Until(tok.ExpiresAt) < 30*time.Second {
		t.Errorf("default expiry: %+v %v", tok, err)
	}
}

// An unreachable site is a plain error: the run then uses the user's credentials.
func TestSiteOCITokensWhenTheSiteIsDown(t *testing.T) {
	withCreds(t, apiKeyCreds(), false)
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Setenv("VULNETIX_WEB_URL", srv.URL)
	srv.Close()
	if _, err := imageTenantTokens(false).OCIToken(context.Background(), "r.example", "a/b"); err == nil {
		t.Fatal("expected an error")
	}
}
