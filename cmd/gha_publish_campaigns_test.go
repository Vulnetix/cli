package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vulnetix/cli/v4/internal/campaigns"
	"github.com/vulnetix/cli/v4/internal/github"
)

const (
	uuidLog4j = "aaaaaaaa-0000-0000-0000-000000000001"
	uuidDone  = "aaaaaaaa-0000-0000-0000-000000000002"
	uuidSame  = "aaaaaaaa-0000-0000-0000-000000000003"
	uuidMoved = "aaaaaaaa-0000-0000-0000-000000000004"
)

// campaignsFixture serves a Vulnetix site API and a GitHub API, and records
// every GitHub write.
type campaignsFixture struct {
	t        *testing.T
	site     *httptest.Server
	gh       *httptest.Server
	mu       sync.Mutex
	writes   []string
	created  []github.CampaignCreate
	patches  map[int]map[string]any
	existing []github.Campaign
	vx       string // the site API's campaigns body
	items    map[string]string
	locked   bool
	siteCode int
}

func newCampaignsFixture(t *testing.T) *campaignsFixture {
	f := &campaignsFixture{t: t, patches: map[int]map[string]any{}, items: map[string]string{}}
	f.site = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer vmt_tok" {
			t.Errorf("site auth %q", r.Header.Get("Authorization"))
		}
		if f.siteCode != 0 {
			w.WriteHeader(f.siteCode)
			fmt.Fprint(w, `{"error":"forbidden","message":"token lacks the campaigns scope"}`)
			return
		}
		if f.locked {
			fmt.Fprint(w, `{"planLocked":true,"feature":"campaigns","campaigns":[]}`)
			return
		}
		if r.URL.Path == "/api/site/v1/campaigns" {
			fmt.Fprint(w, f.vx)
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) == 6 && parts[5] == "items" {
			fmt.Fprint(w, f.items[parts[4]])
			return
		}
		t.Errorf("site: unexpected %s", r.URL)
		w.WriteHeader(404)
	}))
	f.gh = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/orgs/acme/campaigns":
			_ = json.NewEncoder(w).Encode(f.existing)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/web":
			fmt.Fprint(w, `{"id":101}`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/api":
			fmt.Fprint(w, `{"id":102}`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/web/code-scanning/alerts":
			fmt.Fprint(w, `[
			 {"number":3,"rule":{"id":"CVE-1"},"most_recent_instance":{"category":"vulnetix/sca/","message":{"text":"CVE-1 affects log4j@2.14"}}},
			 {"number":4,"rule":{"id":"CVE-9"},"most_recent_instance":{"category":"vulnetix/sca/","message":{"text":"CVE-9 affects other@1"}}},
			 {"number":5,"rule":{"id":"CVE-1"},"most_recent_instance":{"category":"codeql/java","message":{"text":"CVE-1 not ours"}}}]`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/api/code-scanning/alerts":
			fmt.Fprint(w, `[
			 {"number":8,"rule":{"id":"CVE-5"},"most_recent_instance":{"category":"vulnetix/sca/","message":{"text":"CVE-5 affects lodash@4.17.0"}}},
			 {"number":9,"rule":{"id":"CVE-5"},"most_recent_instance":{"category":"vulnetix/sca/","message":{"text":"CVE-5 affects express@4"}}}]`)
		case r.Method == http.MethodPost && r.URL.Path == "/orgs/acme/campaigns":
			var req github.CampaignCreate
			_ = json.NewDecoder(r.Body).Decode(&req)
			f.created = append(f.created, req)
			f.writes = append(f.writes, "POST "+r.URL.Path)
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"number":%d,"name":%q,"state":"open"}`, 100+len(f.created), req.Name)
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/orgs/acme/campaigns/"):
			var n int
			_, _ = fmt.Sscanf(r.URL.Path, "/orgs/acme/campaigns/%d", &n)
			var body map[string]any
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &body)
			f.patches[n] = body
			f.writes = append(f.writes, "PATCH "+r.URL.Path)
			fmt.Fprintf(w, `{"number":%d}`, n)
		default:
			t.Errorf("github: unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(func() { f.site.Close(); f.gh.Close() })
	return f
}

func (f *campaignsFixture) options(dry, recreate bool) campaignsOptions {
	gh := github.NewClient("ghtok")
	gh.BaseURL = f.gh.URL
	sc := newSiteClient(configAuth{Header: "Bearer vmt_tok"}, "campaigns")
	sc.BaseURL = f.site.URL + "/api/site/v1"
	return campaignsOptions{
		Org: "acme", DryRun: dry, Recreate: recreate, DefaultDays: 90,
		ConsoleURL: "https://console.example", Vulnetix: campaigns.New(sc), GitHub: gh,
		Now: func() time.Time { return time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) },
	}
}

const log4jItems = `{"items":[
 {"itemKey":"f1","kind":"finding","repoName":"acme/web","findingId":"CVE-1","packageName":"log4j","state":"open"},
 {"itemKey":"f2","kind":"finding","repoName":"acme/web","findingId":"CVE-2","state":"done"},
 {"itemKey":"d1","kind":"dependency","repoName":"api","packageName":"lodash","state":"open"},
 {"itemKey":"f3","kind":"finding","repoName":"other/elsewhere","findingId":"CVE-1","state":"open"}],
 "pagination":{"totalPages":1}}`

func campaignJSON(uuid, name, status string, deadline int64) string {
	d := ""
	if deadline > 0 {
		d = fmt.Sprintf(`,"deadlineAt":%d`, deadline)
	}
	return fmt.Sprintf(`{"uuid":%q,"name":%q,"description":"Fix it","status":%q%s}`, uuid, name, status, d)
}

func TestCampaignsCreateMapsAlertsAndSetsFields(t *testing.T) {
	f := newCampaignsFixture(t)
	deadline := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC).UnixMilli()
	f.vx = `{"campaigns":[` + campaignJSON(uuidLog4j, "Log4j "+strings.Repeat("x", 60), "ACTIVE", deadline) + `]}`
	f.items[uuidLog4j] = log4jItems
	var out bytes.Buffer
	if err := runCampaignsPublish(context.Background(), f.options(false, false), &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if len(f.created) != 1 {
		t.Fatalf("created %d\n%s", len(f.created), out.String())
	}
	c := f.created[0]
	if !strings.HasPrefix(c.Name, "[Vulnetix] Log4j") || len([]rune(c.Name)) > github.CampaignNameMax {
		t.Fatalf("name %q", c.Name)
	}
	if github.CampaignMarkerOf(c.Description) != uuidLog4j || len(c.Description) > github.CampaignDescriptionMax {
		t.Fatalf("description %q", c.Description)
	}
	if c.EndsAt != "2027-03-01T12:00:00Z" || c.ContactLink != "https://console.example/resolve/campaigns/"+uuidLog4j {
		t.Fatalf("ends/contact %q %q", c.EndsAt, c.ContactLink)
	}
	// web: CVE-1 alert 3 only (4 is another rule, 5 is not Vulnetix's);
	// api: the lodash SCA alert 8 for the dependency item, not express (9).
	// The item in another organization and the done item are not mapped.
	want := map[int][]int{101: {3}, 102: {8}}
	if len(c.CodeScanningAlerts) != 2 {
		t.Fatalf("alerts %+v", c.CodeScanningAlerts)
	}
	for _, g := range c.CodeScanningAlerts {
		if fmt.Sprint(g.AlertNumbers) != fmt.Sprint(want[g.RepositoryID]) {
			t.Fatalf("repo %d alerts %v", g.RepositoryID, g.AlertNumbers)
		}
	}
	if !strings.Contains(out.String(), "skipped") {
		t.Fatalf("the out-of-organization item should be reported:\n%s", out.String())
	}
}

func TestCampaignsDefaultEndIsNinetyDays(t *testing.T) {
	f := newCampaignsFixture(t)
	f.vx = `{"campaigns":[` + campaignJSON(uuidLog4j, "Log4j", "ACTIVE", 0) + `]}`
	f.items[uuidLog4j] = log4jItems
	if err := runCampaignsPublish(context.Background(), f.options(false, false), io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := f.created[0].EndsAt; got != "2027-01-30T00:00:00Z" {
		t.Fatalf("ends_at %q", got)
	}
}

func TestCampaignsCloseCompletedAndArchived(t *testing.T) {
	f := newCampaignsFixture(t)
	f.vx = `{"campaigns":[` + campaignJSON(uuidDone, "Done", "COMPLETED", 0) + `,` + campaignJSON(uuidSame, "Gone", "ARCHIVED", 0) + `]}`
	f.existing = []github.Campaign{
		{Number: 10, Name: "[Vulnetix] Done", State: "open", Description: "x\n" + github.CampaignMarker(uuidDone)},
		{Number: 11, Name: "[Vulnetix] Gone", State: "closed", Description: github.CampaignMarker(uuidSame)},
	}
	if err := runCampaignsPublish(context.Background(), f.options(false, false), io.Discard); err != nil {
		t.Fatal(err)
	}
	if len(f.created) != 0 || len(f.patches) != 1 || f.patches[10]["state"] != "closed" {
		t.Fatalf("created %d patches %v", len(f.created), f.patches)
	}
}

func TestCampaignsUpdateInPlaceWhenScopeIsUnchanged(t *testing.T) {
	f := newCampaignsFixture(t)
	f.vx = `{"campaigns":[` + campaignJSON(uuidSame, "Same", "ACTIVE", 0) + `]}`
	f.items[uuidSame] = log4jItems
	var parsed struct {
		Items []campaigns.Item `json:"items"`
	}
	_ = json.Unmarshal([]byte(log4jItems), &parsed)
	f.existing = []github.Campaign{{
		Number: 12, Name: "[Vulnetix] old name", State: "open", ContactLink: "https://old",
		Description: "old\n" + github.CampaignMarker(uuidSame) + "\n" + scopeMarker(scopeHash(parsed.Items)),
	}}
	if err := runCampaignsPublish(context.Background(), f.options(false, true), io.Discard); err != nil {
		t.Fatal(err)
	}
	if len(f.created) != 0 {
		t.Fatal("a campaign with an unchanged cohort must not be recreated")
	}
	p := f.patches[12]
	if p["name"] != "[Vulnetix] Same" || p["contact_link"] == nil || p["state"] != nil {
		t.Fatalf("patch %v", p)
	}
	if !strings.Contains(fmt.Sprint(p["description"]), scopeMarker(scopeHash(parsed.Items))) {
		t.Fatalf("the scope marker must survive an update: %v", p["description"])
	}
}

func TestCampaignsScopeChange(t *testing.T) {
	setup := func() *campaignsFixture {
		f := newCampaignsFixture(t)
		f.vx = `{"campaigns":[` + campaignJSON(uuidMoved, "Moved", "ACTIVE", 0) + `]}`
		f.items[uuidMoved] = log4jItems
		f.existing = []github.Campaign{{
			Number: 20, Name: "[Vulnetix] Moved", State: "open",
			Description: github.CampaignMarker(uuidMoved) + "\n" + scopeMarker("deadbeef0000"),
		}}
		return f
	}

	t.Run("without the flag it only says so", func(t *testing.T) {
		f := setup()
		var out bytes.Buffer
		if err := runCampaignsPublish(context.Background(), f.options(false, false), &out); err != nil {
			t.Fatal(err)
		}
		if len(f.created) != 0 || !strings.Contains(out.String(), "--recreate-on-scope-change") {
			t.Fatalf("created %d\n%s", len(f.created), out.String())
		}
	})
	t.Run("with the flag it creates first, then closes the old one", func(t *testing.T) {
		f := setup()
		if err := runCampaignsPublish(context.Background(), f.options(false, true), io.Discard); err != nil {
			t.Fatal(err)
		}
		if len(f.created) != 1 || f.patches[20]["state"] != "closed" {
			t.Fatalf("created %d patches %v", len(f.created), f.patches)
		}
		if fmt.Sprint(f.writes) != "[POST /orgs/acme/campaigns PATCH /orgs/acme/campaigns/20]" {
			t.Fatalf("order %v", f.writes)
		}
	})
	t.Run("dry run writes nothing", func(t *testing.T) {
		f := setup()
		var out bytes.Buffer
		if err := runCampaignsPublish(context.Background(), f.options(true, true), &out); err != nil {
			t.Fatal(err)
		}
		if len(f.writes) != 0 || !strings.Contains(out.String(), "would create") {
			t.Fatalf("writes %v\n%s", f.writes, out.String())
		}
	})
}

func TestCampaignsClosedInGitHubStaysClosed(t *testing.T) {
	f := newCampaignsFixture(t)
	f.vx = `{"campaigns":[` + campaignJSON(uuidSame, "Same", "ACTIVE", 0) + `]}`
	f.items[uuidSame] = log4jItems
	f.existing = []github.Campaign{{Number: 5, Name: "[Vulnetix] Same", State: "closed", Description: github.CampaignMarker(uuidSame)}}
	if err := runCampaignsPublish(context.Background(), f.options(false, true), io.Discard); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("a campaign closed on purpose in GitHub was touched: %v", f.writes)
	}
}

func TestCampaignsNothingMatchesIsNotCreated(t *testing.T) {
	f := newCampaignsFixture(t)
	f.vx = `{"campaigns":[` + campaignJSON(uuidLog4j, "Nope", "ACTIVE", 0) + `]}`
	f.items[uuidLog4j] = `{"items":[{"itemKey":"f1","kind":"finding","repoName":"acme/web","findingId":"CVE-404","state":"open"}],"pagination":{"totalPages":1}}`
	var out bytes.Buffer
	if err := runCampaignsPublish(context.Background(), f.options(false, false), &out); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 || !strings.Contains(out.String(), "publish code scanning first") {
		t.Fatalf("writes %v\n%s", f.writes, out.String())
	}
}

func TestCampaignsNotEntitledIsAWarning(t *testing.T) {
	f := newCampaignsFixture(t)
	f.locked = true
	var out bytes.Buffer
	if err := runCampaignsPublish(context.Background(), f.options(false, false), &out); err != nil {
		t.Fatalf("a non-Pro organization is a note, not a failure: %v", err)
	}
	if !strings.Contains(out.String(), "Pro plan") || len(f.writes) != 0 {
		t.Fatalf("%s", out.String())
	}
}

func TestCampaignsMissingScopeNamesTheToken(t *testing.T) {
	f := newCampaignsFixture(t)
	f.siteCode = http.StatusForbidden
	err := runCampaignsPublish(context.Background(), f.options(false, false), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "campaigns read scope") || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("err %v", err)
	}
}

func TestCampaignDescriptionKeepsMarkersWhole(t *testing.T) {
	long := campaigns.Campaign{UUID: uuidLog4j, Description: strings.Repeat("é", 400)}
	d := campaignDescription(long, "abc123")
	if len(d) > github.CampaignDescriptionMax {
		t.Fatalf("len %d", len(d))
	}
	if github.CampaignMarkerOf(d) != uuidLog4j || !strings.Contains(d, scopeMarker("abc123")) {
		t.Fatalf("markers lost: %q", d)
	}
	if !strings.HasPrefix(truncateUTF8("héllo", 2), "h") {
		t.Fatal("truncate split a character")
	}
}
