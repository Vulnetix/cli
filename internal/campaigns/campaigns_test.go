package campaigns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// httpGetter is a Getter over a test server, with a bearer token.
type httpGetter struct {
	base, token string
}

func (g httpGetter) Get(ctx context.Context, path string, q url.Values) ([]byte, error) {
	u := g.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("Authorization", "Bearer "+g.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func TestListAndDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer authentik-jwt" {
			t.Errorf("auth %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/campaigns" || r.URL.Query().Get("includeArchived") != "true" {
			t.Errorf("request %s", r.URL)
		}
		fmt.Fprint(w, `{"campaigns":[
			{"uuid":"u1","name":"Log4j","status":"ACTIVE","deadlineAt":1893456000000},
			{"uuid":"u2","name":"Old","status":"ARCHIVED","archivedAt":5},
			{"uuid":"u3","name":"Done","status":"COMPLETED"}]}`)
	}))
	defer srv.Close()
	got, err := New(httpGetter{srv.URL, "authentik-jwt"}).List(context.Background(), true)
	if err != nil || len(got) != 3 {
		t.Fatalf("%v %+v", err, got)
	}
	if got[0].Closed() || !got[1].Closed() || !got[2].Closed() {
		t.Fatalf("closed: %+v", got)
	}
	d, ok := got[0].Deadline()
	if !ok || !d.Equal(time.UnixMilli(1893456000000).UTC()) {
		t.Fatalf("deadline %v %v", d, ok)
	}
	if _, ok := got[2].Deadline(); ok {
		t.Fatal("no deadline expected")
	}
}

func TestNotEntitledMarkerBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"planLocked":true,"feature":"campaigns","requiredPlan":"pro","campaigns":[]}`)
	}))
	defer srv.Close()
	c := New(httpGetter{srv.URL, "t"})
	if _, err := c.List(context.Background(), false); !errors.Is(err, ErrNotEntitled) {
		t.Fatalf("list: %v", err)
	}
	if _, err := c.Items(context.Background(), "u1", "open"); !errors.Is(err, ErrNotEntitled) {
		t.Fatalf("items: %v", err)
	}
}

func TestItemsPaginatesAndFiltersState(t *testing.T) {
	pages := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/campaigns/u1/items" || r.URL.Query().Get("state") != "open" || r.URL.Query().Get("perPage") != "2" {
			t.Errorf("request %s", r.URL)
		}
		pages++
		switch r.URL.Query().Get("page") {
		case "1":
			fmt.Fprint(w, `{"items":[{"itemKey":"a","state":"open"},{"itemKey":"b","state":"open"}],"pagination":{"totalPages":2}}`)
		case "2":
			fmt.Fprint(w, `{"items":[{"itemKey":"c","state":"open","kind":"dependency","packageName":"lodash"}],"pagination":{"totalPages":2}}`)
		default:
			t.Errorf("unexpected page %s", r.URL.Query().Get("page"))
		}
	}))
	defer srv.Close()
	c := New(httpGetter{srv.URL, "t"})
	c.PerPage = 2
	items, err := c.Items(context.Background(), "u1", "open")
	if err != nil || len(items) != 3 || pages != 2 || items[2].PackageName != "lodash" {
		t.Fatalf("%v pages=%d %+v", err, pages, items)
	}
}

func TestErrorsPropagate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	if _, err := New(httpGetter{srv.URL, "t"}).List(context.Background(), false); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err %v", err)
	}
}
