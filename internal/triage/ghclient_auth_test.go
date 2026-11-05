package triage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// GITHUB_TOKEN cannot read GET /user. That must not read as a bad token.
func TestCheckAuthAcceptsAWorkflowToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Resource not accessible by integration"}`))
	}))
	defer srv.Close()
	c := &GitHubClient{httpClient: srv.Client(), baseURL: srv.URL, token: "t"}
	if login, err := c.CheckAuth(context.Background()); err != nil || login != "github-actions" {
		t.Fatalf("login=%q err=%v", login, err)
	}
}
