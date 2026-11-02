package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/feed"
	"github.com/vulnetix/cli/v3/internal/sensor/host"
)

// stubFeed answers each Fetch with next, then ErrNotModified until next is
// set again.
type stubFeed struct {
	ref  string
	next *feed.Loaded
	err  error
}

func (s *stubFeed) Ref() string { return s.ref }

func (s *stubFeed) Fetch(context.Context) (feed.Loaded, error) {
	if s.err != nil {
		return feed.Loaded{}, s.err
	}
	if s.next == nil {
		return feed.Loaded{}, feed.ErrNotModified
	}
	l := *s.next
	s.next = nil

	return l, nil
}

func iocRule(id, domain string) feed.Rule {
	return feed.Rule{RuleTable: "ioc", RuleUUID: id, RuleType: "IOC_LIST", Name: id, DeployMode: "log", Body: "d " + domain + "\n"}
}

func loaded(etag string, rules ...feed.Rule) *feed.Loaded {
	return &feed.Loaded{FeedType: feed.RuleTypeIOCList, Rules: rules, ETag: etag}
}

func compiledDomains(a *Agent) map[string]bool {
	out := map[string]bool{}
	for d := range a.Rules.Load().IOC.Domains {
		out[d] = true
	}

	return out
}

func TestRefreshKeepsEveryFeedsRules(t *testing.T) {
	one := &stubFeed{ref: "catalog:one", next: loaded("e1", iocRule("r1", "one.example"))}
	two := &stubFeed{ref: "catalog:two", next: loaded("e2", iocRule("r2", "two.example"))}
	a := New(Config{SensorKey: "k", Mode: decide.Monitor, Facts: host.Facts{Hostname: "h"},
		Feeds: []feed.Fetcher{one, two}, Logf: func(string, ...any) {}})
	ctx := context.Background()

	if loads := a.RefreshRules(ctx); len(loads) != 2 {
		t.Fatalf("first refresh loads = %+v", loads)
	}

	// Only the second feed changes; the first answers 304. Both stay compiled.
	two.next = loaded("e2b", iocRule("r2", "two-b.example"))
	loads := a.RefreshRules(ctx)
	if len(loads) != 2 {
		t.Fatalf("second refresh loads = %+v, want both feeds' rules", loads)
	}
	got := compiledDomains(a)
	if !got["one.example"] || !got["two-b.example"] || got["two.example"] {
		t.Fatalf("compiled domains = %v", got)
	}
	if _, ok := a.Verdicts.Rule(decide.RuleRef{Table: "ioc", UUID: "r1"}); !ok {
		t.Fatal("the unchanged feed's rule left the verdict engine")
	}
	if a.etag != "e1e2b" {
		t.Fatalf("ruleset etag = %q, want every feed's", a.etag)
	}

	// A failing feed keeps its last good rules when another changes.
	one.err = errors.New("HTTP 500")
	two.next = loaded("e2c", iocRule("r2", "two-c.example"))
	if loads := a.RefreshRules(ctx); len(loads) != 2 {
		t.Fatalf("third refresh loads = %+v", loads)
	}
	if got := compiledDomains(a); !got["one.example"] || !got["two-c.example"] {
		t.Fatalf("compiled domains = %v", got)
	}

	// Nothing changed: nothing to report.
	if loads := a.RefreshRules(ctx); loads != nil {
		t.Fatalf("unchanged refresh loads = %+v", loads)
	}

	// A feed taken out of the list is dropped even though nothing fetched.
	a.SetFeeds([]feed.Fetcher{two})
	if loads := a.RefreshRules(ctx); len(loads) != 1 || loads[0].RuleUUID != "r2" {
		t.Fatalf("after SetFeeds loads = %+v", loads)
	}
	if got := compiledDomains(a); got["one.example"] {
		t.Fatalf("a removed feed's rules are still compiled: %v", got)
	}
}

func TestRevokedIndicatorFeedStopsReporting(t *testing.T) {
	a, _ := newAgent(t, decide.Monitor)
	revoked := &stubFeed{ref: "catalog:x", err: feed.ErrRevoked}
	a.SetFeeds([]feed.Fetcher{a.cfg.Feeds[0], revoked})
	if loads := a.RefreshRules(context.Background()); len(loads) == 0 {
		t.Fatal("the signed feed still loads")
	}
	if a.reporting() {
		t.Fatal("a revoked credential stops reporting")
	}
}
