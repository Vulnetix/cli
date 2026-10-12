package cmd

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// versionServer answers /discovery and the collection read the way a server of
// one TEA version does, and remembers what it was asked.
type versionServer struct {
	mu       sync.Mutex
	srv      *httptest.Server
	paths    []string
	queries  []url.Values
	status   int
	respBody string
}

func newVersionServer(t *testing.T, status int, body string) *versionServer {
	t.Helper()
	v := &versionServer{status: status, respBody: body}
	v.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v.mu.Lock()
		v.paths = append(v.paths, r.URL.Path)
		v.queries = append(v.queries, r.URL.Query())
		v.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(v.status)
		_, _ = w.Write([]byte(v.respBody))
	}))
	t.Cleanup(v.srv.Close)
	return v
}

func (v *versionServer) lastQuery(t *testing.T) (string, url.Values) {
	t.Helper()
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.paths) == 0 {
		t.Fatal("the server was not asked anything")
	}
	return v.paths[len(v.paths)-1], v.queries[len(v.queries)-1]
}

const discoveryAnswer = `[{"productReleaseUuid":"rel-1","servers":[{"rootUrl":"https://www.vulnetix.com/tea","versions":["1.0.0","0.4.0"]}]}]`

func TestTeaResolveSendsTheSpellingTheServerSpeaks(t *testing.T) {
	teaIsolate(t)
	const urn = "urn:tei:uuid:vulnetix.com:0f9c6b0e-6a0f-5e0e-9e5e-0123456789ab"
	const uri = "tei://vulnetix.com/uuid/0f9c6b0e-6a0f-5e0e-9e5e-0123456789ab"

	cases := []struct{ name, root, in, want string }{
		{"a urn to a 1.0.0 server", "/tea/v1.0.0", urn, uri},
		{"a uri to a 1.0.0 server", "/tea/v1.0.0", uri, uri},
		{"a uri to a 0.4.0 server", "/tea/v0.4.0", uri, urn},
		{"a urn to a 0.4.0 server", "/tea/v0.4.0", urn, urn},
	}
	for _, c := range cases {
		v := newVersionServer(t, http.StatusOK, discoveryAnswer)

		out, _, err := runTea(t, "--server", v.srv.URL+c.root, "resolve", c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		path, q := v.lastQuery(t)
		if path != c.root+"/discovery" || q.Get("tei") != c.want {
			t.Errorf("%s: asked %s?tei=%s, want tei=%s", c.name, path, q.Get("tei"), c.want)
		}
		if !strings.Contains(out, "rel-1") || !strings.Contains(out, "1.0.0, 0.4.0") {
			t.Errorf("%s: output %q", c.name, out)
		}
	}
}

func TestTeaResolveTakesAPurlDirectlyFromA1_0_0Server(t *testing.T) {
	teaIsolate(t)
	v := newVersionServer(t, http.StatusOK, discoveryAnswer)

	if _, _, err := runTea(t, "--server", v.srv.URL+"/tea/v1.0.0", "resolve", "pkg:github/acme/widget"); err != nil {
		t.Fatal(err)
	}
	path, q := v.lastQuery(t)
	if path != "/tea/v1.0.0/discovery" || q.Get("purl") != "pkg:github/acme/widget" || q.Has("tei") {
		t.Errorf("asked %s?%s", path, q.Encode())
	}
}

// A 0.4.0 server has no purl parameter and says so with a 400. The answer should
// tell the user what to do, not only that it failed.
func TestTeaResolveExplainsWhatToDoWhenTheServerCannotTakeAPurl(t *testing.T) {
	teaIsolate(t)
	v := newVersionServer(t, http.StatusBadRequest, `{"error":"INVALID_REQUEST","message":"tei query parameter is required"}`)

	_, _, err := runTea(t, "--server", v.srv.URL+"/tea/v0.4.0", "resolve", "pkg:github/acme/widget")
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"does not take a purl directly", "tei://", "purl"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}
}

func TestTeaCollectionShowsWhenItWasMadeUnderEitherVersion(t *testing.T) {
	teaIsolate(t)
	for name, body := range map[string]string{
		"1.0.0": `{"uuid":"r","version":3,"createdDate":"2026-10-01T00:00:00Z","updateReason":{"type":"VEX_UPDATED"},"artifacts":[]}`,
		"0.4.0": `{"uuid":"r","version":3,"date":"2026-10-01T00:00:00Z","updateReason":{"type":"VEX_UPDATED"},"artifacts":[]}`,
	} {
		v := newVersionServer(t, http.StatusOK, body)

		out, _, err := runTea(t, "--server", v.srv.URL+"/tea/v"+name, "collection", "rel-1")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(out, "collection v3") || !strings.Contains(out, "2026-10-01T00:00:00Z") {
			t.Errorf("%s: output %q does not show the version and when it was made", name, out)
		}
	}
}
