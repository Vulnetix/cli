package ghactx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchOIDCTokenSendsAudienceAndBearer(t *testing.T) {
	var gotAudience, gotAuth, gotOther string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAudience = r.URL.Query().Get("audience")
		gotOther = r.URL.Query().Get("api-version")
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"value":"eyJ.header.sig"}`))
	}))
	defer srv.Close()

	// GitHub hands out a URL that already has a query string.
	tok := fetchOIDCToken(context.Background(), srv.Client(), srv.URL+"/token?api-version=2.0", "req-token")
	if tok != "eyJ.header.sig" {
		t.Fatalf("token = %q", tok)
	}
	if gotAudience != OIDCAudience {
		t.Errorf("audience = %q, want %q", gotAudience, OIDCAudience)
	}
	if gotOther != "2.0" {
		t.Errorf("existing query lost: api-version = %q", gotOther)
	}
	if gotAuth != "bearer req-token" {
		t.Errorf("authorization = %q", gotAuth)
	}
}

func TestFetchOIDCTokenFailsQuietly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/denied":
			http.Error(w, "no id-token permission", http.StatusForbidden)
		default:
			_, _ = w.Write([]byte(`not json`))
		}
	}))
	defer srv.Close()

	cases := map[string][2]string{
		"no url":      {"", "t"},
		"no token":    {srv.URL + "/ok", ""},
		"http error":  {srv.URL + "/denied", "t"},
		"bad body":    {srv.URL + "/garbage", "t"},
		"unreachable": {"http://127.0.0.1:1/token", "t"},
	}
	for name, c := range cases {
		if got := fetchOIDCToken(context.Background(), srv.Client(), c[0], c[1]); got != "" {
			t.Errorf("%s: token = %q, want empty", name, got)
		}
	}
}
