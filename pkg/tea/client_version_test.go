package tea

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// recorder is a TEA server that remembers what it was asked and answers with the
// body it is given.
type recorder struct {
	srv    *httptest.Server
	method []string
	path   []string
	query  []url.Values
	status int
	body   string
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	r := &recorder{status: http.StatusOK, body: `{}`}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.method = append(r.method, req.Method)
		r.path = append(r.path, req.URL.Path)
		r.query = append(r.query, req.URL.Query())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(r.status)
		_, _ = w.Write([]byte(r.body))
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *recorder) last(t *testing.T) (method, path string, query url.Values) {
	t.Helper()
	if len(r.path) == 0 {
		t.Fatal("the server was not asked anything")
	}
	i := len(r.path) - 1
	return r.method[i], r.path[i], r.query[i]
}

func TestDefaultsAreTheCurrentSpecification(t *testing.T) {
	if DefaultServer != "https://www.vulnetix.com/tea/v1.0.0" || PublicServer != "https://www.vulnetix.com/tea/public/v1.0.0" {
		t.Errorf("defaults are %s and %s", DefaultServer, PublicServer)
	}
	if got := VersionFromRoot(DefaultServer); got != "1.0.0" {
		t.Errorf("the default server names version %q, want 1.0.0", got)
	}
	if VersionFromRoot(LegacyServer) != "0.4.0" || VersionFromRoot(LegacyPublicServer) != "0.4.0" {
		t.Error("the legacy roots do not name 0.4.0")
	}
}

func TestIsPublicServerRecognisesEveryPublicRoot(t *testing.T) {
	for in, want := range map[string]bool{
		PublicServer:                                      true,
		LegacyPublicServer:                                true,
		"https://www.vulnetix.com/tea/public/v1":          true,
		"HTTPS://WWW.VULNETIX.COM/tea/public/v1.0.0/":     true,
		DefaultServer:                                     false,
		LegacyServer:                                      false,
		"https://www.vulnetix.com/tea/v1":                 false,
		"https://elsewhere.example.com/tea/public/v1.0.0": false,
	} {
		if got := IsPublicServer(in); got != want {
			t.Errorf("IsPublicServer(%q) = %v, want %v", in, got, want)
		}
	}
}

// Publication is not part of any TEA version, so it is not at the version path.
func TestPublicationBase(t *testing.T) {
	for in, want := range map[string]string{
		"https://www.vulnetix.com/tea/v1.0.0":        "https://www.vulnetix.com/tea/v1",
		"https://www.vulnetix.com/tea/v1.0.0/":       "https://www.vulnetix.com/tea/v1",
		"https://www.vulnetix.com/tea/v0.4.0":        "https://www.vulnetix.com/tea/v1",
		"https://www.vulnetix.com/tea/v1":            "https://www.vulnetix.com/tea/v1",
		"http://localhost:3000/tea/v1.0.0":           "http://localhost:3000/tea/v1",
		"https://tea.example.com/v1.0.0":             "https://tea.example.com/v1.0.0", // not Vulnetix-shaped: left alone
		"https://tea.example.com/custom/root":        "https://tea.example.com/custom/root",
		"https://www.vulnetix.com/tea/public/v1.0.0": "https://www.vulnetix.com/tea/public/v1.0.0",
	} {
		if got := PublicationBase(in); got != want {
			t.Errorf("PublicationBase(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReadsGoToTheVersionPathAndWritesGoToTheStableAlias(t *testing.T) {
	r := newRecorder(t)
	r.body = `{"uuid":"p-1","name":"widget"}`
	c := New(r.srv.URL+"/tea/v1.0.0", nil)
	ctx := context.Background()

	if _, err := c.Product(ctx, "p-1"); err != nil {
		t.Fatal(err)
	}
	if m, p, _ := r.last(t); m != "GET" || p != "/tea/v1.0.0/product/p-1" {
		t.Errorf("a read went to %s %s", m, p)
	}

	if _, err := c.CreateProduct(ctx, "widget", nil, ""); err != nil {
		t.Fatal(err)
	}
	if m, p, _ := r.last(t); m != "POST" || p != "/tea/v1/product" {
		t.Errorf("a publication went to %s %s, want POST /tea/v1/product", m, p)
	}

	if err := c.DeleteProduct(ctx, "p-1"); err != nil {
		t.Fatal(err)
	}
	if m, p, _ := r.last(t); m != "DELETE" || p != "/tea/v1/product/p-1" {
		t.Errorf("a delete went to %s %s", m, p)
	}

	if _, err := c.AccessPolicy(ctx, "p-1"); err != nil {
		t.Fatal(err)
	}
	if _, p, _ := r.last(t); p != "/tea/v1/accessPolicy/p-1" {
		t.Errorf("the access policy was read from %s", p)
	}
}

func TestACustomRootKeepsEverythingAtThatRoot(t *testing.T) {
	r := newRecorder(t)
	c := New(r.srv.URL+"/custom", nil)
	ctx := context.Background()

	_, _ = c.Product(ctx, "p-1")
	if _, p, _ := r.last(t); p != "/custom/product/p-1" {
		t.Errorf("a read went to %s", p)
	}
	_, _ = c.CreateProduct(ctx, "widget", nil, "")
	if _, p, _ := r.last(t); p != "/custom/product" {
		t.Errorf("a publication went to %s; publication is Vulnetix's extension and a root of another shape serves it where it serves the rest", p)
	}
}

func TestPublishURLOverridesTheDerivedBase(t *testing.T) {
	r := newRecorder(t)
	c := New(r.srv.URL+"/tea/v1.0.0", nil)
	c.PublishURL = r.srv.URL + "/elsewhere/"

	_, _ = c.CreateProduct(context.Background(), "widget", nil, "")
	if _, p, _ := r.last(t); p != "/elsewhere/product" {
		t.Errorf("a publication went to %s", p)
	}
}

func TestResolveTEIIsSentInTheSpellingTheServerSpeaks(t *testing.T) {
	const urn = "urn:tei:uuid:vulnetix.com:0f9c6b0e-6a0f-5e0e-9e5e-0123456789ab"
	const uri = "tei://vulnetix.com/uuid/0f9c6b0e-6a0f-5e0e-9e5e-0123456789ab"
	r := newRecorder(t)
	r.body = `[]`

	cases := []struct{ name, root, in, want string }{
		{"a urn to a 1.0.0 root", "/tea/v1.0.0", urn, uri},
		{"a uri to a 0.4.0 root", "/tea/v0.4.0", uri, urn},
		{"a uri to the alias, which names no version, is sent as typed", "/tea/v1", uri, uri},
		{"a urn to the alias is sent as typed", "/tea/v1", urn, urn},
	}
	for _, c := range cases {
		client := New(r.srv.URL+c.root, nil)
		if _, err := client.ResolveTEI(context.Background(), c.in); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if _, _, q := r.last(t); q.Get("tei") != c.want {
			t.Errorf("%s: sent tei=%q, want %q", c.name, q.Get("tei"), c.want)
		}
	}
}

func TestResolvePURLUsesThePurlParameter(t *testing.T) {
	r := newRecorder(t)
	r.body = `[{"productReleaseUuid":"r-1","servers":[{"rootUrl":"https://x.example.com/tea","versions":["1.0.0","0.4.0"]}]}]`
	c := New(r.srv.URL+"/tea/v1.0.0", nil)

	out, err := c.ResolvePURL(context.Background(), "pkg:github/acme/widget")
	if err != nil {
		t.Fatal(err)
	}
	_, path, q := r.last(t)
	if path != "/tea/v1.0.0/discovery" || q.Get("purl") != "pkg:github/acme/widget" || q.Has("tei") {
		t.Errorf("asked %s?%s", path, q.Encode())
	}
	if len(out) != 1 || out[0].ProductReleaseUUID != "r-1" || strings.Join(out[0].Servers[0].Versions, ",") != "1.0.0,0.4.0" {
		t.Errorf("decoded %+v", out)
	}
}

// The release read differs between the versions; the caller sees one shape.
func TestComponentReleaseDecodesBothShapes(t *testing.T) {
	wrapped := `{"release":{"uuid":"c-1","component":"comp","componentName":"widget","version":"1.2.3","createdDate":"2026-10-01T00:00:00Z",
		"distributions":[{"distributionId":"d-1","url":"https://example.com/w.zip"}]},
		"latestCollection":{"uuid":"c-1","version":2,"date":"2026-09-30T00:00:00Z"}}`
	flat := `{"uuid":"c-1","component":"comp","componentName":"widget","version":"1.2.3","createdDate":"2026-10-01T00:00:00Z",
		"distributions":[{"distributionId":"d-1","url":"https://example.com/w.zip"}],
		"latestCollection":{"uuid":"c-1","version":2,"createdDate":"2026-09-30T00:00:00Z"}}`

	for name, body := range map[string]string{"0.4.0 wrapped": wrapped, "1.0.0 flat": flat} {
		var d ComponentReleaseDetail
		if err := json.Unmarshal([]byte(body), &d); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d.Release.UUID != "c-1" || d.Release.Version != "1.2.3" || d.Release.ComponentName != "widget" {
			t.Errorf("%s: release = %+v", name, d.Release.Release)
		}
		if len(d.Release.Distributions) != 1 || d.Release.Distributions[0].URL != "https://example.com/w.zip" {
			t.Errorf("%s: distributions = %+v", name, d.Release.Distributions)
		}
		if d.LatestCollection.Version != 2 || d.LatestCollection.When() != "2026-09-30T00:00:00Z" {
			t.Errorf("%s: collection = %+v (When %q)", name, d.LatestCollection, d.LatestCollection.When())
		}
	}
}

func TestComponentReleaseReadThroughTheClient(t *testing.T) {
	r := newRecorder(t)
	r.body = `{"uuid":"c-1","version":"9.9.9","distributions":[{"distributionId":"d-1"}],"latestCollection":{"uuid":"c-1","version":1,"createdDate":"2026-10-01T00:00:00Z"}}`
	c := New(r.srv.URL+"/tea/v1.0.0", nil)

	d, err := c.ComponentRelease(context.Background(), "c-1")
	if err != nil {
		t.Fatal(err)
	}
	if d.Release.Version != "9.9.9" || len(d.Release.Distributions) != 1 {
		t.Errorf("decoded %+v", d.Release)
	}
	if _, p, _ := r.last(t); p != "/tea/v1.0.0/componentRelease/c-1" {
		t.Errorf("read %s", p)
	}
}

func TestComponentReleaseOutputKeepsTheWrappedShape(t *testing.T) {
	var d ComponentReleaseDetail
	d.Release.UUID = "c-1"
	d.LatestCollection.Version = 3

	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]json.RawMessage
	_ = json.Unmarshal(b, &out)
	if _, ok := out["release"]; !ok {
		t.Errorf("--json output lost its release key: %s", b)
	}
}

func TestCollectionWhenPrefersTheNewerField(t *testing.T) {
	for _, c := range []struct {
		col  Collection
		want string
	}{
		{Collection{CreatedDate: "new", Date: "old"}, "new"},
		{Collection{CreatedDate: "new"}, "new"},
		{Collection{Date: "old"}, "old"},
		{Collection{}, ""},
	} {
		if got := c.col.When(); got != c.want {
			t.Errorf("%+v.When() = %q, want %q", c.col, got, c.want)
		}
	}
}

// 1.0.0 leaves nextPageToken out of the last page; 0.4.0 sent an empty string.
func TestPageReadsBothEnvelopes(t *testing.T) {
	for name, body := range map[string]string{
		"1.0.0 last page": `{"hasNext":false,"results":[{"uuid":"a","name":"x"}]}`,
		"0.4.0 last page": `{"hasNext":false,"nextPageToken":"","results":[{"uuid":"a","name":"x"}]}`,
	} {
		r := newRecorder(t)
		r.body = body
		page, err := New(r.srv.URL+"/tea/v1.0.0", nil).Products(context.Background(), 0, "")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if page.HasNext || page.NextPageToken != "" || len(page.Results) != 1 {
			t.Errorf("%s: %+v", name, page)
		}
	}

	r := newRecorder(t)
	r.body = `{"hasNext":true,"nextPageToken":"abc","results":[]}`
	page, _ := New(r.srv.URL+"/tea/v1.0.0", nil).Products(context.Background(), 0, "")
	if !page.HasNext || page.NextPageToken != "abc" {
		t.Errorf("a middle page: %+v", page)
	}
}

func TestErrorsNameTheCodesAOneDotZeroServerUses(t *testing.T) {
	for _, c := range []struct {
		code string
		is   func(*Error) bool
	}{
		{"NOT_IMPLEMENTED", (*Error).IsNotImplemented},
		{"INVALID_PAGE_TOKEN", (*Error).IsInvalidPageToken},
		{"SIGNATURE_NOT_FOUND", (*Error).IsSignatureNotFound},
		{"NO_ACCEPTABLE_FORMAT", (*Error).IsNoAcceptableFormat},
		{"OBJECT_UNKNOWN", (*Error).IsNotFound},
	} {
		r := newRecorder(t)
		r.status = http.StatusBadRequest
		if c.code == "OBJECT_UNKNOWN" || c.code == "NOT_IMPLEMENTED" || c.code == "SIGNATURE_NOT_FOUND" {
			r.status = http.StatusNotFound
		}
		r.body = `{"error":"` + c.code + `","message":"because"}`

		_, err := New(r.srv.URL+"/tea/v1.0.0", nil).Product(context.Background(), "x")
		var apiErr *Error
		if !errors.As(err, &apiErr) {
			t.Fatalf("%s: %v is not a TEA error", c.code, err)
		}
		if !c.is(apiErr) {
			t.Errorf("%s was not recognised by its helper: %+v", c.code, apiErr)
		}
		if !strings.Contains(apiErr.Error(), c.code) || !strings.Contains(apiErr.Error(), "because") {
			t.Errorf("%s reads as %q", c.code, apiErr.Error())
		}
	}

	// And no helper claims a code that is not its own.
	e := &Error{Status: 404, Code: "OBJECT_UNKNOWN"}
	if e.IsNotImplemented() || e.IsInvalidPageToken() || e.IsSignatureNotFound() || e.IsNoAcceptableFormat() {
		t.Error("an unknown-object error was taken for another code")
	}
}

func TestClientVersionComesFromItsRoot(t *testing.T) {
	for root, want := range map[string]string{
		"https://x.example.com/tea/v1.0.0": "1.0.0",
		"https://x.example.com/tea/v0.4.0": "0.4.0",
		"https://x.example.com/tea/v1":     "",
		"https://x.example.com/anything":   "",
	} {
		if got := New(root, nil).Version(); got != want {
			t.Errorf("New(%q).Version() = %q, want %q", root, got, want)
		}
	}
}
