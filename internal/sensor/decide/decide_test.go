package decide

import (
	"fmt"
	"testing"
	"time"
)

var (
	t0   = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	vp   = RuleRef{Table: "virtual_patch", UUID: "vp-1"}
	logR = RuleRef{Table: "virtual_patch", UUID: "vp-log"}
)

func engine(mode Mode) *Engine {
	e := New(mode, Config{Hold: 15 * time.Minute, BreakerSubjects: 3, BreakerWindow: 5 * time.Minute})
	e.SetRules([]Rule{
		{Ref: vp, Mode: Block, Verified: true},
		{Ref: logR, Mode: Log, Verified: true},
	})

	return e
}

func match(subject string) Match {
	return Match{Rule: vp, Subject: subject, Reversible: true}
}

func TestMonitorNeverBlocks(t *testing.T) {
	e := engine(Monitor)
	if v := e.Decide(match("POST /upload"), t0); v.Action != Allowed {
		t.Fatalf("monitor = %+v", v)
	}
}

func TestGuardHoldsThenLapsesToAllow(t *testing.T) {
	e := engine(Guard)
	v := e.Decide(match("POST /upload"), t0)
	if v.Action != Held || !v.HoldUntil.Equal(t0.Add(15*time.Minute)) {
		t.Fatalf("first match = %+v", v)
	}
	if v := e.Decide(match("POST /upload"), t0.Add(time.Minute)); v.Action != Held {
		t.Fatalf("the same subject inside the hold stays held: %+v", v)
	}
	if got := e.Pending(t0.Add(time.Minute)); len(got) != 1 {
		t.Fatalf("pending = %v", got)
	}

	lapsed := t0.Add(16 * time.Minute)
	if v := e.Decide(match("POST /upload"), lapsed); v.Action != Allowed {
		t.Fatalf("after the hold lapses = %+v", v)
	}
	// Not held again: guard by neglect must not become enforce.
	if v := e.Decide(match("POST /upload"), lapsed.Add(time.Hour)); v.Action != Allowed {
		t.Fatalf("a lapsed subject was held again: %+v", v)
	}
}

func TestGuardNeverHoldsWhatItCannotUndo(t *testing.T) {
	e := engine(Guard)
	m := match("/tmp/.x/miner")
	m.Reversible = false
	if v := e.Decide(m, t0); v.Action != Allowed {
		t.Fatalf("an irreversible action was held: %+v", v)
	}
}

func TestEnforceBlocksIrreversibleToo(t *testing.T) {
	e := engine(Enforce)
	m := match("/tmp/.x/miner")
	m.Reversible = false
	if v := e.Decide(m, t0); v.Action != Blocked {
		t.Fatalf("enforce = %+v", v)
	}
}

func TestLogRulesAndUnverifiedFeedsNeverBlock(t *testing.T) {
	e := engine(Enforce)
	if v := e.Decide(Match{Rule: logR, Subject: "x", Reversible: true}, t0); v.Action != Allowed {
		t.Fatalf("a log-only rule blocked: %+v", v)
	}
	e.SetRules([]Rule{{Ref: vp, Mode: Block, Verified: false}})
	if v := e.Decide(match("x"), t0); v.Action != Allowed {
		t.Fatalf("an unverified rule blocked: %+v", v)
	}
	if v := e.Decide(Match{Rule: RuleRef{Table: "virtual_patch", UUID: "nope"}, Subject: "x"}, t0); v.Action != Allowed {
		t.Fatal("an unknown rule is never acted on")
	}
}

func TestHealthChecksAreNeverHeld(t *testing.T) {
	e := engine(Guard)
	m := match("GET /healthz")
	m.HealthCheck = true
	if v := e.Decide(m, t0); v.Action != Allowed {
		t.Fatalf("health check = %+v", v)
	}
}

func TestBreakerRevertsAMisfiringRule(t *testing.T) {
	e := engine(Guard)
	for i := range 3 {
		if v := e.Decide(match(fmt.Sprintf("GET /p%d", i)), t0.Add(time.Duration(i)*time.Second)); v.Action != Held {
			t.Fatalf("hold %d = %+v", i, v)
		}
	}
	if v := e.Decide(match("GET /p4"), t0.Add(4*time.Second)); v.Action != Allowed {
		t.Fatalf("the fourth distinct subject in the window should trip the breaker: %+v", v)
	}
	if len(e.Tripped()) != 1 {
		t.Fatal("tripped rule not reported")
	}
	if v := e.Decide(match("GET /p5"), t0.Add(time.Hour)); v.Action != Allowed {
		t.Fatal("an open breaker stays open until a person decides")
	}

	e.Apply(Decision{UUID: "d1", Rule: vp, Subject: "*", Verdict: "promote"})
	if len(e.Tripped()) != 0 {
		t.Fatal("a decision about the rule closes its breaker")
	}
}

func TestBreakerWindowSlides(t *testing.T) {
	e := engine(Guard)
	for i := range 6 {
		at := t0.Add(time.Duration(i) * 3 * time.Minute)
		if v := e.Decide(match(fmt.Sprintf("GET /slow%d", i)), at); v.Action != Held {
			t.Fatalf("hold %d spread over time = %+v", i, v)
		}
	}
}

func TestConfirmedBlockAndFalsePositive(t *testing.T) {
	e := engine(Guard)
	e.Decide(match("POST /upload"), t0)

	e.Apply(Decision{UUID: "b1", Rule: vp, Subject: "*", Verdict: "block", Until: t0.Add(90 * 24 * time.Hour)})
	if v := e.Decide(match("POST /upload"), t0.Add(time.Minute)); v.Action != Blocked {
		t.Fatalf("a confirmed block = %+v", v)
	}
	if len(e.Pending(t0)) != 0 {
		t.Fatal("a decision resolves the holds it is about")
	}
	if v := e.Decide(match("POST /upload"), t0.Add(91*24*time.Hour)); v.Action == Blocked && v.Reason == "block confirmed by a person" {
		t.Fatal("a block past its until no longer applies")
	}

	e.Apply(Decision{UUID: "b1", Revoked: true})
	e.Apply(Decision{UUID: "fp", Rule: vp, Subject: "*", Verdict: "allow"})
	if v := e.Decide(match("GET /anything"), t0.Add(2*time.Minute)); v.Action != Allowed || v.Reason != "marked a false positive" {
		t.Fatalf("false positive = %+v", v)
	}
}

func TestAllowOnceIsOneSubject(t *testing.T) {
	e := engine(Guard)
	e.Decide(match("POST /a"), t0)
	e.Apply(Decision{UUID: "a1", Rule: vp, Subject: "POST /a", Verdict: "allow"})
	if v := e.Decide(match("POST /a"), t0.Add(time.Minute)); v.Action != Allowed {
		t.Fatalf("allowed subject = %+v", v)
	}
	if v := e.Decide(match("POST /b"), t0.Add(time.Minute)); v.Action != Held {
		t.Fatalf("another subject is still held: %+v", v)
	}
}

func TestMonitorOutranksAConfirmedBlock(t *testing.T) {
	e := engine(Guard)
	e.Apply(Decision{UUID: "b", Rule: vp, Subject: "*", Verdict: "block"})
	e.Apply(Decision{Verdict: "mode", Value: "monitor"})
	if v := e.Decide(match("x"), t0); v.Action != Allowed {
		t.Fatalf("monitor blocks nothing, confirmed or not: %+v", v)
	}
}

func TestPromoteSurvivesAReloadAndRevokeRestoresTheFeedMode(t *testing.T) {
	e := engine(Enforce)
	e.Apply(Decision{UUID: "p", Rule: logR, Subject: "*", Verdict: "promote"})
	e.SetRules([]Rule{{Ref: logR, Mode: Log, Verified: true}})
	if r, _ := e.Rule(logR); r.Mode != Block {
		t.Fatal("a promote decision must outlive a feed refresh")
	}
	e.Apply(Decision{UUID: "p", Revoked: true})
	if r, _ := e.Rule(logR); r.Mode != Log {
		t.Fatal("revoking the promote returns the rule to the feed's mode")
	}
}

func TestUnknownModeIsMonitor(t *testing.T) {
	if New("chaos", Config{}).Mode() != Monitor {
		t.Fatal("an unknown mode must fall back to monitor")
	}
	e := New(Guard, Config{})
	e.Apply(Decision{Verdict: "mode", Value: "chaos"})
	if e.Mode() != Guard {
		t.Fatal("an unknown mode decision is ignored")
	}
}
