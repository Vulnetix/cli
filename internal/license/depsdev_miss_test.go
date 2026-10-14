package license

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestDepsDevNotFoundIsRememberedButFailuresAreNot(t *testing.T) {
	var hits atomic.Int64
	status := atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	old := depsDevBaseURL
	depsDevBaseURL = srv.URL
	defer func() { depsDevBaseURL = old }()

	status.Store(http.StatusInternalServerError)
	for i := 0; i < 2; i++ {
		depsDevCache.Delete("npm:flaky-pkg:1.0.0")
		FetchLicenseFromDepsDev("flaky-pkg", "1.0.0", "npm")
	}
	if hits.Load() != 2 {
		t.Fatalf("a 500 was remembered: %d requests for two lookups, want 2", hits.Load())
	}

	hits.Store(0)
	status.Store(http.StatusNotFound)
	for i := 0; i < 3; i++ {
		depsDevCache.Delete("npm:private-pkg:1.0.0")
		if lic := FetchLicenseFromDepsDev("private-pkg", "1.0.0", "npm"); lic != "" {
			t.Fatalf("lic = %q", lic)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("a 404 was asked %d times in three lookups, want once", hits.Load())
	}
}
