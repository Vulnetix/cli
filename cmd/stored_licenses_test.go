package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/internal/license"
)

func TestLookupStoredLicensesUsesPersistenceKeys(t *testing.T) {
	var sent []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/cli.licenses") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var env struct {
			Payload struct {
				Keys []string `json:"keys"`
			} `json:"payload"`
		}
		_ = json.Unmarshal(body, &env)
		sent = env.Payload.Keys
		_, _ = w.Write([]byte(`{"meta":{},"data":{"licenses":{"pkg:npm/left-pad@1.3.0":"WTFPL"}}}`))
	}))
	defer srv.Close()
	t.Setenv("VULNETIX_API_URL", srv.URL)

	got := lookupStoredLicenses([]license.PackageLicense{
		{PackageName: "left-pad", PackageVersion: "1.3.0", Ecosystem: "npm"},
		{PackageName: "other", PackageVersion: "2.0.0", Ecosystem: "npm"},
	})
	if len(sent) != 2 || sent[0] != "pkg:npm/left-pad@1.3.0" {
		t.Fatalf("sent keys %v, want the purls persistence keys Dependency rows by", sent)
	}
	if len(got) != 1 || got[0] != "WTFPL" {
		t.Fatalf("got %v, want {0: WTFPL}", got)
	}
}
