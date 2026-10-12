package tea

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServerForCatalogue(t *testing.T) {
	cases := map[string]string{
		"":            DefaultServer,
		"first-party": DefaultServer,
		" Public ":    PublicServer,
		"public":      PublicServer,
	}
	for in, want := range cases {
		got, err := ServerForCatalogue(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}
	_, err := ServerForCatalogue("mirror")
	if err == nil || !strings.Contains(err.Error(), "first-party, public") {
		t.Errorf("unknown catalogue error = %v", err)
	}
}

func TestIsPublicServer(t *testing.T) {
	for in, want := range map[string]bool{
		PublicServer:       true,
		PublicServer + "/": true,
		strings.ToUpper(PublicServer[:5]) + PublicServer[5:]: true,
		DefaultServer:                       false,
		"https://example.com/tea/public/v1": false,
		"":                                  false,
	} {
		if got := IsPublicServer(in); got != want {
			t.Errorf("IsPublicServer(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestValidIDType(t *testing.T) {
	for in, want := range map[string]string{"purl": "PURL", " TEI ": "TEI", "cpe": "CPE", "compliance_document": "COMPLIANCE_DOCUMENT"} {
		if got, ok := ValidIDType(in); !ok || got != want {
			t.Errorf("%q: got %q %v", in, got, ok)
		}
	}
	if _, ok := ValidIDType("ISBN"); ok {
		t.Error("ISBN is not a server identifier type")
	}
}

func TestListOptionsQuery(t *testing.T) {
	if got := (ListOptions{}).Query().Encode(); got != "" {
		t.Errorf("zero options should send nothing, got %q", got)
	}
	q := ListOptions{PageSize: 100, PageToken: "tea1:25", IDType: "PURL", IDValue: "pkg:github/a/b",
		SortField: "name", SortOrder: "desc"}.Query()
	for k, v := range map[string]string{"pageSize": "100", "pageToken": "tea1:25", "idType": "PURL",
		"idValue": "pkg:github/a/b", "sortField": "name", "sortOrder": "desc"} {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
}

func TestListCallsReachTheirEndpoints(t *testing.T) {
	var path, query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, query = r.URL.Path, r.URL.RawQuery
		_, _ = io.WriteString(w, `{"results":[{"uuid":"u1","name":"n1","identifiers":[{"idType":"PURL","idValue":"pkg:github/a/b"}]}],"hasNext":true,"nextPageToken":"tea1:1"}`)
	}))
	defer srv.Close()
	c := New(srv.URL, nil)

	comps, err := c.ListComponents(context.Background(), ListOptions{PageSize: 10})
	if err != nil || path != "/components" || query != "pageSize=10" {
		t.Fatalf("components: %v %s ?%s", err, path, query)
	}
	if !comps.HasNext || comps.NextPageToken != "tea1:1" || comps.Results[0].Identifiers[0].IDValue != "pkg:github/a/b" {
		t.Errorf("page = %+v", comps)
	}

	// The original signature still works and still reaches /products.
	prods, err := c.Products(context.Background(), 5, "tea1:9")
	if err != nil || path != "/products" || query != "pageSize=5&pageToken=tea1%3A9" {
		t.Fatalf("products: %v %s ?%s", err, path, query)
	}
	if len(prods.Results) != 1 {
		t.Errorf("page = %+v", prods)
	}
}

func TestClientErrBlocksTheRequest(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	c := New(srv.URL, nil)
	c.Err = io.ErrClosedPipe
	if err := c.Do(context.Background(), "GET", "/products", nil, nil, nil); err != io.ErrClosedPipe || hit {
		t.Errorf("err = %v, hit = %v", err, hit)
	}
}
