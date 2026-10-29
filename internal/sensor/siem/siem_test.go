package siem

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
)

var at = time.Date(2026, 10, 30, 9, 15, 0, 0, time.FixedZone("AEST", 10*3600))

func TestDNSRowMapsAMatch(t *testing.T) {
	ev := DNSRow("build-7", DNSDecision{
		Time: at, Client: "10.0.0.5:5353", QName: "C2.Evil.Example.", QType: "A", RCode: "NXDOMAIN",
		Match: &Match{Rule: decide.RuleRef{Table: "countermeasure", UUID: "cm-1"}, Indicator: "evil.example",
			Verdict: decide.Verdict{Action: decide.Held, Reason: "held for a decision", HoldUntil: at.Add(15 * time.Minute)}},
	})
	if ev.Table != "dns_events" {
		t.Fatalf("table = %q", ev.Table)
	}
	r := ev.Row
	want := map[string]any{
		"ts": "2026-10-29T23:15:00Z", "host": "build-7", "qname": "c2.evil.example", "qtype": "A",
		"rcode": "NXDOMAIN", "action": "block", "policy": "countermeasure:cm-1", "src_ip": "10.0.0.5",
	}
	for k, v := range want {
		if r[k] != v {
			t.Errorf("%s = %v, want %v", k, r[k], v)
		}
	}
	if a, ok := r["answers"].([]string); !ok || len(a) != 0 {
		t.Errorf("answers must be an empty list, got %#v", r["answers"])
	}
	raw := r["raw"].(map[string]any)
	if raw["decision"] != "held" || raw["indicator"] != "evil.example" || raw["hold_until"] != "2026-10-29T23:30:00Z" {
		t.Errorf("raw = %v", raw)
	}
	if _, ok := r["tenant"]; ok {
		t.Error("a row never carries a tenant")
	}
}

func TestDNSRowWithNoMatchIsAnAllow(t *testing.T) {
	r := DNSRow("h", DNSDecision{Time: at, QName: "example.com", QType: "AAAA", RCode: "NOERROR", Answers: []string{"2001:db8::1"}}).Row
	if r["action"] != "allow" || r["policy"] != nil || r["src_ip"] != nil {
		t.Fatalf("row = %v", r)
	}
	if a := r["answers"].([]string); len(a) != 1 || a[0] != "2001:db8::1" {
		t.Fatalf("answers = %v", a)
	}
}

func TestEgressRowMapsAConnection(t *testing.T) {
	r := EgressRow("build-7", EgressDecision{
		Time: at, Client: "127.0.0.1:40001", Target: "API.Example.com:443", RemoteAddr: "93.184.216.34:443",
		Method: "CONNECT", Bytes: 4096,
		Match: &Match{Rule: decide.RuleRef{Table: "virtual_patch", UUID: "vp-1"}, Verdict: decide.Verdict{Action: decide.Allowed, Reason: "monitor mode"}},
	}).Row
	want := map[string]any{
		"ts": "2026-10-29T23:15:00Z", "host": "build-7", "src_ip": "127.0.0.1", "src_port": 40001,
		"dst_ip": "93.184.216.34", "dst_port": 443, "dst_host": "api.example.com", "proto": "tcp",
		"bytes": int64(4096), "action": "allow", "direction": "egress", "policy": "virtual_patch:vp-1",
	}
	for k, v := range want {
		if r[k] != v {
			t.Errorf("%s = %#v, want %#v", k, r[k], v)
		}
	}
	if raw := r["raw"].(map[string]any); raw["method"] != "CONNECT" || raw["reason"] != "monitor mode" {
		t.Errorf("raw = %v", raw)
	}
}

func TestEgressRowToAnAddressAndARefusal(t *testing.T) {
	r := EgressRow("h", EgressDecision{Time: at, Target: "[2001:db8::7]:8443",
		Match: &Match{Verdict: decide.Verdict{Action: decide.Blocked}}}).Row
	if r["dst_ip"] != "2001:db8::7" || r["dst_port"] != 8443 || r["dst_host"] != nil || r["action"] != "block" {
		t.Fatalf("row = %v", r)
	}
}

// server records what Guardian would receive.
type server struct {
	mu       sync.Mutex
	requests []request
	auth     []string
	status   int
}

func (s *server) handler(w http.ResponseWriter, r *http.Request) {
	var body request
	_ = json.NewDecoder(r.Body).Decode(&body)
	s.mu.Lock()
	s.requests = append(s.requests, body)
	s.auth = append(s.auth, r.Header.Get("Authorization"))
	status := s.status
	s.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":"unauthorised"}`))

		return
	}
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (s *server) count() (requests, events int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.requests {
		events += len(r.Events)
	}

	return len(s.requests), events
}

func start(t *testing.T, status int) (*server, string) {
	t.Helper()
	s := &server{status: status}
	srv := httptest.NewServer(http.HandlerFunc(s.handler))
	t.Cleanup(srv.Close)

	return s, srv.URL
}

func TestFlushPostsTheEventsRouteShape(t *testing.T) {
	s, u := start(t, 0)
	f := &Forwarder{URL: u, Token: "gdn_test", Host: "h", Logf: t.Logf}
	f.DNS(DNSDecision{Time: at, QName: "example.com", QType: "A", RCode: "NOERROR"})
	f.Egress(EgressDecision{Time: at, Target: "example.com:443"})
	f.Flush(context.Background())

	if len(s.requests) != 1 || s.auth[0] != "Bearer gdn_test" {
		t.Fatalf("requests = %d, auth = %v", len(s.requests), s.auth)
	}
	req := s.requests[0]
	if req.Source != "sensor" || len(req.Events) != 2 || req.Events[0].Table != "dns_events" || req.Events[1].Table != "net_events" {
		t.Fatalf("body = %+v", req)
	}
	if f.Pending() != 0 || f.Dropped() != 0 {
		t.Fatalf("pending %d dropped %d", f.Pending(), f.Dropped())
	}
}

func TestFlushNeverSendsMoreThanTheRouteTakes(t *testing.T) {
	s, u := start(t, 0)
	f := &Forwarder{URL: u, Token: "gdn_test", BatchSize: 9000, Limit: 12000, Logf: t.Logf}
	for i := 0; i < 11000; i++ {
		f.DNS(DNSDecision{Time: at, QName: fmt.Sprintf("n%d.example", i)})
	}
	f.Flush(context.Background())
	n, events := s.count()
	if n != 3 || events != 11000 {
		t.Fatalf("%d requests carried %d events, want 3 and 11000", n, events)
	}
	for _, r := range s.requests {
		if len(r.Events) > maxPerRequest {
			t.Fatalf("a request carried %d events", len(r.Events))
		}
	}
}

func TestTheBufferDropsTheOldestAndCountsThem(t *testing.T) {
	f := &Forwarder{Token: "gdn_test", Limit: 5, BatchSize: 1000}
	for i := 0; i < 8; i++ {
		f.DNS(DNSDecision{Time: at, QName: fmt.Sprintf("n%d.example", i)})
	}
	if f.Pending() != 5 || f.Dropped() != 3 {
		t.Fatalf("pending %d dropped %d, want 5 and 3", f.Pending(), f.Dropped())
	}
	if first := f.buf[0].Row["qname"]; first != "n3.example" {
		t.Fatalf("oldest kept = %v, want n3.example", first)
	}
}

func TestTheDefaultBound(t *testing.T) {
	f := &Forwarder{Token: "gdn_test"}
	for i := 0; i < defaultLimit+10; i++ {
		f.Egress(EgressDecision{Time: at})
	}
	if f.Pending() != defaultLimit || f.Dropped() != 10 {
		t.Fatalf("pending %d dropped %d", f.Pending(), f.Dropped())
	}
}

func TestAFailedBatchIsDroppedAndLoggedOncePerMinute(t *testing.T) {
	s, u := start(t, http.StatusUnauthorized)
	var logs []string
	clock := at
	f := &Forwarder{URL: u, Token: "gdn_bad", Now: func() time.Time { return clock },
		Logf: func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }}

	for round := 0; round < 3; round++ {
		f.DNS(DNSDecision{Time: at, QName: "example.com"})
		f.Flush(context.Background())
		clock = clock.Add(20 * time.Second)
	}
	if n, _ := s.count(); n != 3 {
		t.Fatalf("each flush tries once: %d requests", n)
	}
	if f.Pending() != 0 || f.Dropped() != 3 {
		t.Fatalf("a failed batch is dropped, not retried: pending %d dropped %d", f.Pending(), f.Dropped())
	}
	if len(logs) != 1 {
		t.Fatalf("logged %d times within a minute: %v", len(logs), logs)
	}

	clock = clock.Add(time.Minute)
	f.DNS(DNSDecision{Time: at, QName: "example.com"})
	f.Flush(context.Background())
	if len(logs) != 2 {
		t.Fatalf("a minute later it logs again: %v", logs)
	}
}

func TestAnUnreachableServerIsAFailureNotAHang(t *testing.T) {
	var logs int
	f := &Forwarder{URL: "http://127.0.0.1:1/v1/ingest/events", Token: "gdn_test", Logf: func(string, ...any) { logs++ }}
	f.Egress(EgressDecision{Time: at})
	done := make(chan struct{})
	go func() {
		f.Flush(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("flush outlived its timeout")
	}
	if f.Dropped() != 1 || logs != 1 {
		t.Fatalf("dropped %d, logs %d", f.Dropped(), logs)
	}
}

func TestRunFlushesWhenABatchFills(t *testing.T) {
	s, u := start(t, 0)
	f := &Forwarder{URL: u, Token: "gdn_test", BatchSize: 10, FlushEvery: time.Hour, Logf: t.Logf}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		f.Run(ctx)
		close(done)
	}()
	for i := 0; i < 10; i++ {
		f.DNS(DNSDecision{Time: at, QName: "example.com"})
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, events := s.count(); events == 10 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a full batch was not sent before the timer")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// What is left when the sensor stops goes in a last flush.
	f.Egress(EgressDecision{Time: at})
	cancel()
	<-done
	if _, events := s.count(); events != 11 {
		t.Fatalf("events = %d after the last flush, want 11", events)
	}
}

func TestRunFlushesOnTheTimer(t *testing.T) {
	s, u := start(t, 0)
	f := &Forwarder{URL: u, Token: "gdn_test", FlushEvery: 20 * time.Millisecond, Logf: t.Logf}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Run(ctx)
	f.DNS(DNSDecision{Time: at, QName: "example.com"})
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, events := s.count(); events == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the timer did not flush")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Adding never waits on the network, even while a post hangs.
func TestAddingNeverBlocksOnASlowServer(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	f := &Forwarder{URL: srv.URL, Token: "gdn_test", BatchSize: 1, FlushEvery: time.Hour, Logf: t.Logf}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Run(ctx)
	start := time.Now()
	for i := 0; i < 5000; i++ {
		f.DNS(DNSDecision{Time: at, QName: "example.com"})
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("adding 5000 events took %v while the server hung", d)
	}
}
