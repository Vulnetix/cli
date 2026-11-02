package github

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureReleaseAndUploadAsset(t *testing.T) {
	var srv *httptest.Server
	deleted, created, uploaded := false, false, ""
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/releases/tags/v1":
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"message":"Not Found"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/o/r/releases":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["draft"] != true {
				t.Errorf("a created release must be a draft: %+v", body)
			}
			created = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": 1, "tag_name": "v1", "upload_url": srv.URL + "/upload/1/assets{?name,label}",
				"assets": []map[string]any{{"id": 9, "name": "sbom.cdx.json"}},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/repos/o/r/releases/assets/9":
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/upload/1/assets":
			b, _ := io.ReadAll(r.Body)
			uploaded = r.URL.Query().Get("name") + "=" + string(b)
			_, _ = io.WriteString(w, `{"id":10,"name":"sbom.cdx.json","size":2}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.String())
		}
	}))
	defer srv.Close()
	c := NewClient("tok")
	c.BaseURL = srv.URL

	if _, _, err := c.EnsureRelease(context.Background(), "o/r", "v1", false); !IsStatus(err, http.StatusNotFound) {
		t.Fatalf("without create a missing release is a 404, got %v", err)
	}
	rel, made, err := c.EnsureRelease(context.Background(), "o/r", "v1", true)
	if err != nil || !made || !created {
		t.Fatalf("%v %v", err, made)
	}
	p := filepath.Join(t.TempDir(), "sbom.cdx.json")
	_ = os.WriteFile(p, []byte("{}"), 0o644)
	if _, err := c.UploadAsset(context.Background(), "o/r", rel, p, "", false); err == nil {
		t.Fatal("a duplicate name without clobber must fail")
	}
	a, err := c.UploadAsset(context.Background(), "o/r", rel, p, "", true)
	if err != nil || a.ID != 10 || !deleted || uploaded != "sbom.cdx.json={}" {
		t.Fatalf("%+v %v deleted=%v uploaded=%q", a, err, deleted, uploaded)
	}
}
