package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/engine"
	"github.com/vulnetix/cli/v3/internal/sensor/feed"
	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
)

var now = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

type events struct {
	mu  sync.Mutex
	all []uplink.Event
}

func (e *events) add(ev uplink.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.all = append(e.all, ev)
}

func setup(t *testing.T, mode decide.Mode, rules []feed.Rule) (*Rules, *decide.Engine) {
	t.Helper()
	set, results := engine.Compile(rules)
	var loaded []decide.Rule
	for _, r := range results {
		if r.Status == engine.Compiled {
			loaded = append(loaded, decide.Rule{Ref: decide.RuleRef{Table: r.Rule.RuleTable, UUID: r.Rule.RuleUUID}, Mode: decide.RuleMode(r.Rule.DeployMode), Verified: true})
		}
	}
	verdicts := decide.New(mode, decide.Config{})
	verdicts.SetRules(loaded)
	holder := &Rules{}
	holder.Store(set)

	return holder, verdicts
}

var traversal = feed.Rule{RuleTable: "virtual_patch", RuleUUID: "vp-1", RuleType: "MODSECURITY", DeployMode: "block",
	Body: `SecRule ARGS "@contains ../" "id:910001,phase:2,deny,msg:'path traversal'"`}

func upstream(t *testing.T) (*url.URL, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write([]byte("upstream saw " + string(body)))
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)

	return u, &calls
}

func TestReverseHoldsInGuardAndReports(t *testing.T) {
	up, calls := upstream(t)
	rules, verdicts := setup(t, decide.Guard, []feed.Rule{traversal})
	rec := &events{}
	p := &Reverse{Upstream: up, Rules: rules, Verdicts: verdicts, Report: rec.add, Now: func() time.Time { return now }}

	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "/get?f=../../etc/passwd", nil))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "held for review") {
		t.Fatalf("held request = %d %q", w.Code, w.Body.String())
	}
	if *calls != 0 {
		t.Fatal("a held request reached the upstream")
	}
	if len(rec.all) != 1 || rec.all[0].Action != "held" || rec.all[0].HoldExpiresAt == 0 || rec.all[0].Lane != "virtual-patch" {
		t.Fatalf("event = %+v", rec.all)
	}
	if rec.all[0].Subject != "GET /get" {
		t.Fatalf("the subject is the method and path, not the query: %q", rec.all[0].Subject)
	}
}

func TestReverseMonitorPassesThroughWithTheWholeBody(t *testing.T) {
	up, calls := upstream(t)
	rules, verdicts := setup(t, decide.Monitor, []feed.Rule{traversal})
	rec := &events{}
	p := &Reverse{Upstream: up, Rules: rules, Verdicts: verdicts, Report: rec.add, BodyLimit: 4}

	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("POST", "/x?f=../a", strings.NewReader("abcdefgh")))
	if w.Code != http.StatusOK || *calls != 1 {
		t.Fatalf("monitor = %d calls %d", w.Code, *calls)
	}
	if w.Body.String() != "upstream saw abcdefgh" {
		t.Fatalf("the upstream must get the whole body even past the inspection limit: %q", w.Body.String())
	}
	if len(rec.all) != 1 || rec.all[0].Action != "allowed" {
		t.Fatalf("monitor still reports: %+v", rec.all)
	}
}

func TestReverseNeverHoldsAHealthCheck(t *testing.T) {
	up, calls := upstream(t)
	rules, verdicts := setup(t, decide.Guard, []feed.Rule{traversal})
	p := &Reverse{Upstream: up, Rules: rules, Verdicts: verdicts, HealthPaths: []string{"/healthz"}}

	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "/healthz?x=../", nil))
	if w.Code != http.StatusOK || *calls != 1 {
		t.Fatalf("health check = %d", w.Code)
	}
}

func TestReverseFailsOpenBeforeRulesLoad(t *testing.T) {
	up, calls := upstream(t)
	p := &Reverse{Upstream: up, Rules: &Rules{}, Verdicts: decide.New(decide.Enforce, decide.Config{})}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "/a?f=../", nil))
	if w.Code != http.StatusOK || *calls != 1 {
		t.Fatal("no rules loaded yet means no inspection, not no traffic")
	}
}

func TestEgressBlocksAnIndicatorInEnforce(t *testing.T) {
	stix := feed.Rule{RuleTable: "countermeasure", RuleUUID: "cm-1", RuleType: "STIX", DeployMode: "block",
		Body: `{"type":"bundle","objects":[{"type":"indicator","pattern":"[domain-name:value = 'evil.example']"}]}`}
	rules, verdicts := setup(t, decide.Enforce, []feed.Rule{stix})
	rec := &events{}
	p := &Egress{Rules: rules, Verdicts: verdicts, Report: rec.add}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodConnect, "https://c2.evil.example:443", nil)
	r.Host = "c2.evil.example:443"
	p.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("CONNECT to an indicator = %d", w.Code)
	}
	if len(rec.all) != 1 || rec.all[0].SubjectKind != "connection" || rec.all[0].Action != "blocked" || rec.all[0].Lane != "countermeasure" {
		t.Fatalf("event = %+v", rec.all)
	}

	up, calls := upstream(t)
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", up.String()+"/fine", nil)
	p.ServeHTTP(w, r)
	if w.Code != http.StatusOK || *calls != 1 {
		t.Fatalf("a clean destination = %d", w.Code)
	}
}
