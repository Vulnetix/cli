package vdb

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/pkg/auth"
)

func TestNewClient(t *testing.T) {
	c := NewClient("test-org", "test-secret")
	if c.BaseURL != DefaultBaseURL {
		t.Errorf("expected %q, got %q", DefaultBaseURL, c.BaseURL)
	}
	if c.APIVersion != DefaultAPIVersion {
		t.Errorf("expected %q, got %q", DefaultAPIVersion, c.APIVersion)
	}
	if c.OrgID != "test-org" {
		t.Errorf("expected 'test-org', got %q", c.OrgID)
	}
	if c.AuthMethod != auth.SigV4 {
		t.Errorf("expected SigV4, got %q", c.AuthMethod)
	}
}

func TestNewClientFromCredentials(t *testing.T) {
	creds := &auth.Credentials{
		OrgID:  "test-org",
		APIKey: "test-key",
		Method: auth.DirectAPIKey,
	}
	c := NewClientFromCredentials(creds)
	if c.OrgID != "test-org" {
		t.Errorf("expected 'test-org', got %q", c.OrgID)
	}
	if c.APIKey != "test-key" {
		t.Errorf("expected 'test-key', got %q", c.APIKey)
	}
	if c.AuthMethod != auth.DirectAPIKey {
		t.Errorf("expected DirectAPIKey, got %q", c.AuthMethod)
	}
}

func TestDefaultConstants(t *testing.T) {
	if DefaultBaseURL == "" {
		t.Error("expected non-empty DefaultBaseURL")
	}
	if DefaultAPIVersion == "" {
		t.Error("expected non-empty DefaultAPIVersion")
	}
	if Region == "" {
		t.Error("expected non-empty Region")
	}
	if MaxRetries < 0 {
		t.Error("expected non-negative MaxRetries")
	}
}

func TestRateLimitInfo(t *testing.T) {
	r := RateLimitInfo{
		DayLimit:  1000,
		Remaining: 500,
		Plan:      "community",
	}
	if r.DayLimit != 1000 || r.Remaining != 500 {
		t.Errorf("unexpected values: %+v", r)
	}
}

func TestErrorResponse(t *testing.T) {
	e := ErrorResponse{
		Success: false,
		Error:   "not found",
		Details: "resource does not exist",
	}
	if e.Error != "not found" {
		t.Errorf("expected 'not found', got %q", e.Error)
	}
}

func TestTokenCache(t *testing.T) {
	tc := TokenCache{
		Token: "test-token",
	}
	if tc.Token != "test-token" {
		t.Errorf("expected 'test-token', got %q", tc.Token)
	}
}

func TestTokenResponse(t *testing.T) {
	tr := TokenResponse{
		Token: "jwt-token",
		Sub:   "test-sub",
	}
	if tr.Token != "jwt-token" || tr.Sub != "test-sub" {
		t.Errorf("unexpected values: %+v", tr)
	}
}

func TestGetDerivedAPIKey(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"orgId":"org","apiKey":"key"}`))
	}))
	defer srv.Close()

	c := NewClient("org", "secret")
	c.BaseURL = srv.URL
	c.APIVersion = "/v2"

	resp, err := c.GetDerivedAPIKey()
	if err != nil {
		t.Fatalf("GetDerivedAPIKey: %v", err)
	}
	if resp.OrgID != "org" || resp.APIKey != "key" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if gotPath != "/v2/auth/api-key" {
		t.Fatalf("path = %q", gotPath)
	}
	if !strings.Contains(gotAuth, "Credential=org/") {
		t.Fatalf("Authorization header missing credential org: %q", gotAuth)
	}
}
