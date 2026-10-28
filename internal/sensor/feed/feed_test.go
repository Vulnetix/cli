package feed

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fixture struct {
	files map[string][]byte
	etag  string
	hits  map[string]int
}

func (f *fixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/feed/")
	f.hits[name]++
	body, ok := f.files[name]
	if !ok {
		http.NotFound(w, r)

		return
	}
	if name == manifestName {
		if r.Header.Get("If-None-Match") == f.etag {
			w.WriteHeader(http.StatusNotModified)

			return
		}
		w.Header().Set("ETag", f.etag)
	}
	_, _ = w.Write(body)
}

func newFixture(t *testing.T, key ed25519.PrivateKey) (*fixture, *httptest.Server) {
	t.Helper()
	rules, _ := json.Marshal(map[string]any{"rules": []Rule{
		{RuleTable: "virtual_patch", RuleUUID: "vp-1", RuleType: "MODSECURITY", DeployMode: "block", Body: `SecRule ARGS "@contains ../" "id:1,deny"`},
	}})
	sum := sha256.Sum256(rules)
	manifestDoc, _ := json.Marshal(map[string]any{
		"feedUuid": "f1", "feedType": "MODSECURITY",
		"files": []map[string]string{{"filename": rulesName, "sha256": hex.EncodeToString(sum[:])}},
	})
	f := &fixture{files: map[string][]byte{manifestName: manifestDoc, rulesName: rules}, etag: `"v1"`, hits: map[string]int{}}
	if key != nil {
		f.files[manifestName+".sig"] = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, manifestDoc)))
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)

	return f, srv
}

func TestSignedFeedLoadsVerified(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f, srv := newFixture(t, priv)
	src := &Source{BaseURL: srv.URL + "/feed/", PublicKey: pub}

	got, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Verified || len(got.Rules) != 1 || got.Rules[0].DeployMode != "block" {
		t.Fatalf("loaded = %+v", got)
	}

	if _, err := src.Fetch(context.Background()); !errors.Is(err, ErrNotModified) {
		t.Fatalf("second fetch = %v, want not modified", err)
	}
	if f.hits[rulesName] != 1 {
		t.Fatal("an unchanged manifest must not refetch the rules")
	}
}

func TestUnsignedOrWronglySignedFeedLoadsUnverified(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)

	_, unsigned := newFixture(t, nil)
	got, err := (&Source{BaseURL: unsigned.URL + "/feed", PublicKey: pub}).Fetch(context.Background())
	if err != nil || got.Verified || got.Unverified != "feed is not signed" {
		t.Fatalf("unsigned = %+v %v", got, err)
	}

	_, wrong := newFixture(t, other)
	got, err = (&Source{BaseURL: wrong.URL + "/feed", PublicKey: pub}).Fetch(context.Background())
	if err != nil || got.Verified || !strings.Contains(got.Unverified, "pinned key") {
		t.Fatalf("wrong key = %+v %v", got, err)
	}

	got, err = (&Source{BaseURL: wrong.URL + "/feed"}).Fetch(context.Background())
	if err != nil || got.Verified || got.Unverified != "no feed key pinned" {
		t.Fatalf("no key = %+v %v", got, err)
	}
}

func TestTamperedRulesAreRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f, srv := newFixture(t, priv)
	f.files[rulesName] = []byte(`{"rules":[{"ruleUuid":"evil","deployMode":"block"}]}`)

	if _, err := (&Source{BaseURL: srv.URL + "/feed", PublicKey: pub}).Fetch(context.Background()); err == nil {
		t.Fatal("rules.json that does not match the signed manifest must not load")
	}
}

func TestPlainHTTPIsRefusedExceptLoopback(t *testing.T) {
	for _, u := range []string{"http://feeds.example.com/x", "ftp://x/y", "not a url"} {
		if _, err := checkBase(u); err == nil {
			t.Errorf("checkBase(%q) accepted", u)
		}
	}
	for _, u := range []string{"https://vulnetix.com/feeds/o/f", "http://127.0.0.1:8080/f"} {
		if _, err := checkBase(u); err != nil {
			t.Errorf("checkBase(%q) = %v", u, err)
		}
	}
}

func TestParsePublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	if k, err := ParsePublicKey(base64.StdEncoding.EncodeToString(pub)); err != nil || !k.Equal(pub) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := ParsePublicKey("c2hvcnQ="); err == nil {
		t.Fatal("a short key was accepted")
	}
}
