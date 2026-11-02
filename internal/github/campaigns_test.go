package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCampaignMarkerAndNameLimits(t *testing.T) {
	m := CampaignMarker("11111111-2222-3333-4444-555555555555")
	if got := CampaignMarkerOf("text\n" + m + "\nmore"); got != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("marker %q", got)
	}
	if CampaignMarkerOf("no marker") != "" {
		t.Fatal("expected none")
	}
	n := CampaignName(strings.Repeat("é", 80))
	if len([]rune(n)) != CampaignNameMax || !strings.HasPrefix(n, "[Vulnetix] ") {
		t.Fatalf("name %q", n)
	}
	if got := CampaignEnd(time.Date(2027, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600))); got != "2027-01-02T02:04:05Z" {
		t.Fatalf("end %q", got)
	}
}

func TestListCreatePatchCampaigns(t *testing.T) {
	var srv *httptest.Server
	var created CampaignCreate
	var patched map[string]any
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/orgs/acme/campaigns":
			if r.URL.Query().Get("page") == "2" {
				fmt.Fprint(w, `[{"number":2,"name":"b","state":"closed"}]`)
				return
			}
			w.Header().Set("Link", fmt.Sprintf(`<%s/orgs/acme/campaigns?page=2>; rel="next"`, srv.URL))
			fmt.Fprint(w, `[{"number":1,"name":"a","state":"open"}]`)
		case r.Method == http.MethodPost && r.URL.Path == "/orgs/acme/campaigns":
			_ = json.NewDecoder(r.Body).Decode(&created)
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"number":7,"name":"x","state":"open"}`)
		case r.Method == http.MethodPatch && r.URL.Path == "/orgs/acme/campaigns/7":
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &patched)
			fmt.Fprint(w, `{"number":7,"state":"closed"}`)
		case r.URL.Path == "/repos/acme/web":
			fmt.Fprint(w, `{"id":42}`)
		case r.URL.Path == "/repos/acme/web/code-scanning/alerts":
			if r.URL.Query().Get("state") != "open" {
				t.Errorf("alerts query %s", r.URL.RawQuery)
			}
			fmt.Fprint(w, `[{"number":5,"rule":{"id":"CVE-1"},"most_recent_instance":{"category":"vulnetix/sca/","message":{"text":"CVE-1 affects lodash@4"}}}]`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := NewClient("tok")
	c.BaseURL = srv.URL
	ctx := context.Background()

	list, err := c.ListCampaigns(ctx, "acme")
	if err != nil || len(list) != 2 || list[1].State != CampaignClosed {
		t.Fatalf("%v %+v", err, list)
	}
	got, err := c.CreateCampaign(ctx, "acme", CampaignCreate{
		Name: "[Vulnetix] x", Description: "d", EndsAt: "2027-01-01T00:00:00Z",
		CodeScanningAlerts: []CampaignAlerts{{RepositoryID: 42, AlertNumbers: []int{5}}},
	})
	if err != nil || got.Number != 7 {
		t.Fatalf("%v %+v", err, got)
	}
	if created.CodeScanningAlerts[0].RepositoryID != 42 || created.GenerateIssues {
		t.Fatalf("body %+v", created)
	}
	if _, err := c.PatchCampaign(ctx, "acme", 7, CampaignPatch{State: CampaignClosed}); err != nil {
		t.Fatal(err)
	}
	if len(patched) != 1 || patched["state"] != "closed" {
		t.Fatalf("an empty field must not be sent: %v", patched)
	}
	id, err := c.RepositoryID(ctx, "acme/web")
	if err != nil || id != 42 {
		t.Fatalf("id %d %v", id, err)
	}
	alerts, err := c.ListOpenAlerts(ctx, "acme/web")
	if err != nil || len(alerts) != 1 || alerts[0].Rule.ID != "CVE-1" || alerts[0].MostRecentInstance.Category != "vulnetix/sca/" {
		t.Fatalf("%v %+v", err, alerts)
	}
}

func TestCampaignPermissionIsSoft(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message":"Resource not accessible by integration"}`)
	}))
	defer srv.Close()
	c := NewClient("tok")
	c.BaseURL = srv.URL
	_, err := c.ListCampaigns(context.Background(), "acme")
	if !IsPermission(err) {
		t.Fatalf("err %v", err)
	}
}
