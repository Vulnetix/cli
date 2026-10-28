package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/feed"
	"github.com/vulnetix/cli/v3/internal/sensor/host"
	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
	"github.com/vulnetix/cli/v3/pkg/auth"
)

// platform is a fake vdb-site runtime API plus a published feed.
type platform struct {
	mu        sync.Mutex
	registers []map[string]json.RawMessage
	events    []uplink.Event
	failPosts bool
	decisions []uplink.Decision
	files     map[string][]byte
	inventory []byte
}

func (p *platform) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	switch {
	case strings.HasPrefix(r.URL.Path, "/feed/"):
		b, ok := p.files[strings.TrimPrefix(r.URL.Path, "/feed/")]
		if !ok {
			http.NotFound(w, r)

			return
		}
		_, _ = w.Write(b)
	case r.URL.Path == "/v1/runtime/sensors/register":
		var m map[string]json.RawMessage
		_ = json.Unmarshal(body, &m)
		p.registers = append(p.registers, m)
		_, _ = w.Write([]byte(`{"sensorUuid":"s-1"}`))
	case r.URL.Path == "/v1/runtime/events":
		if p.failPosts {
			w.WriteHeader(http.StatusBadGateway)

			return
		}
		var in struct {
			Events []uplink.Event `json:"events"`
		}
		_ = json.Unmarshal(body, &in)
		p.events = append(p.events, in.Events...)
		_, _ = w.Write([]byte(`{"accepted":1}`))
	case r.URL.Path == "/v1/runtime/inventory":
		p.inventory = body
		_, _ = w.Write([]byte(`{"stored":1}`))
	case r.URL.Path == "/v1/runtime/decisions":
		out, _ := json.Marshal(map[string]any{"decisions": p.decisions, "cursor": 99})
		p.decisions = nil
		_, _ = w.Write(out)
	}
}

func publish(t *testing.T, p *platform, key ed25519.PrivateKey, rules []feed.Rule) {
	t.Helper()
	rulesJSON, _ := json.Marshal(map[string]any{"rules": rules})
	sum := sha256.Sum256(rulesJSON)
	manifest, _ := json.Marshal(map[string]any{"feedUuid": "f", "files": []map[string]string{{"filename": "rules.json", "sha256": hex.EncodeToString(sum[:])}}})
	p.files = map[string][]byte{
		"manifest.json":     manifest,
		"rules.json":        rulesJSON,
		"manifest.json.sig": []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, manifest))),
	}
}

func newAgent(t *testing.T, mode decide.Mode) (*Agent, *platform) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	p := &platform{}
	publish(t, p, priv, []feed.Rule{
		{RuleTable: "virtual_patch", RuleUUID: "vp-1", RuleType: "MODSECURITY", DeployMode: "block",
			Body: `SecRule ARGS "@contains ../" "id:910001,phase:2,deny"`},
		{RuleTable: "virtual_patch", RuleUUID: "sn-1", RuleType: "SNORT", Body: "alert tcp any any -> any any (sid:1;)"},
	})
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)

	a := New(Config{
		SensorKey: "k", Version: "test", Mode: mode, Facts: host.Facts{ComputeKind: "ec2", Hostname: "h"},
		Feeds:  []*feed.Source{{BaseURL: srv.URL + "/feed", PublicKey: pub}},
		Uplink: &uplink.Client{Endpoint: srv.URL, Creds: &auth.Credentials{Method: auth.SigV4, OrgID: "o", Secret: "s"}},
		Logf:   func(string, ...any) {},
	})

	return a, p
}

func TestRefreshCompilesAndReportsEveryRule(t *testing.T) {
	a, p := newAgent(t, decide.Guard)
	ctx := context.Background()

	loads := a.RefreshRules(ctx)
	if len(loads) != 2 {
		t.Fatalf("loads = %+v", loads)
	}
	byID := map[string]uplink.RuleLoad{}
	for _, l := range loads {
		byID[l.RuleUUID] = l
	}
	if byID["vp-1"].Status != "compiled" || byID["vp-1"].Mode != "block" || byID["sn-1"].Status != "no-engine" {
		t.Fatalf("loads = %+v", byID)
	}
	if r, ok := a.Verdicts.Rule(decide.RuleRef{Table: "virtual_patch", UUID: "vp-1"}); !ok || !r.Verified {
		t.Fatal("a rule from a signed feed loads verified")
	}
	if err := a.register(ctx, loads); err != nil {
		t.Fatal(err)
	}
	var caps map[string]bool
	_ = json.Unmarshal(p.registers[0]["capabilities"], &caps)
	if caps["bpfLsm"] || caps["ebpf"] || caps["ptrace"] {
		t.Fatalf("the sensor claimed a capability it does not use: %v", caps)
	}
}

func TestEventsSurviveAnOutageAndReportDrops(t *testing.T) {
	a, p := newAgent(t, decide.Monitor)
	a.cfg.QueueLimit = 2
	ctx := context.Background()

	p.failPosts = true
	for _, k := range []string{"a", "b", "c"} {
		a.Enqueue(uplink.Event{EventKey: k})
	}
	a.Flush(ctx)
	if len(a.queue) != 2 || a.dropped != 1 {
		t.Fatalf("queue = %d dropped = %d", len(a.queue), a.dropped)
	}

	p.failPosts = false
	a.Flush(ctx)
	if len(p.events) != 2 || p.events[0].EventKey != "b" {
		t.Fatalf("posted = %+v", p.events)
	}
	if p.events[0].Detail["droppedBefore"] != float64(1) {
		t.Fatalf("the gap must be reported with the next batch: %+v", p.events[0].Detail)
	}
}

func TestDecisionsApplyAndRevoke(t *testing.T) {
	d := ToDecision(uplink.Decision{UUID: "x", RuleTable: "virtual_patch", RuleUUID: "r", Verdict: "block", Until: 5000, RevokedAt: 7})
	if !d.Revoked || d.Subject != "*" || d.Until.UnixMilli() != 5000 {
		t.Fatalf("decision = %+v", d)
	}

	a, p := newAgent(t, decide.Guard)
	p.decisions = []uplink.Decision{{UUID: "m", Verdict: "mode", Value: "enforce"}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.decisionLoop(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for a.Verdicts.Mode() != decide.Enforce && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if a.Verdicts.Mode() != decide.Enforce {
		t.Fatal("a mode decision was not applied")
	}
}

func TestReportInventoryFromTheHost(t *testing.T) {
	a, p := newAgent(t, decide.Monitor)
	root := t.TempDir()
	mk := func(rel, body string) {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("var/lib/dpkg/status", "Package: libssl3\nStatus: install ok installed\nVersion: 3.0.11-1\n\n")
	mk("var/lib/dpkg/info/libssl3:amd64.list", "/usr/lib/x86_64-linux-gnu/libssl.so.3\n")
	mk("proc/10/maps", "7f00-7f01 r-xp 00000000 fd:01 1 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n")
	a.cfg.HostRoot = root

	if err := a.ReportInventory(context.Background()); err != nil {
		t.Fatal(err)
	}
	var sent struct {
		SensorKey string                    `json:"sensorKey"`
		Packages  []uplink.InventoryPackage `json:"packages"`
	}
	if err := json.Unmarshal(p.inventory, &sent); err != nil {
		t.Fatal(err)
	}
	if sent.SensorKey != "k" || len(sent.Packages) != 1 || sent.Packages[0].State != "stale-loaded" || sent.Packages[0].Ecosystem != "deb" {
		t.Fatalf("sent = %+v", sent)
	}

	a.cfg.HostRoot = t.TempDir()
	if err := a.ReportInventory(context.Background()); err == nil {
		t.Fatal("a host with no readable processes is an error, not an empty report")
	}
}

func TestHostChecksQueueOncePerDay(t *testing.T) {
	a, _ := newAgent(t, decide.Monitor)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc", "ssh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "ssh", "sshd_config"), []byte("PermitRootLogin yes\nPasswordAuthentication no\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a.cfg.HostRoot = root
	day := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)

	if n := a.ReportHostChecks(day); n != 1 {
		t.Fatalf("findings = %d", n)
	}
	a.ReportHostChecks(day.Add(6 * time.Hour))
	a.ReportHostChecks(day.Add(24 * time.Hour))
	if len(a.queue) != 3 {
		t.Fatalf("queued = %d", len(a.queue))
	}
	ev := a.queue[0]
	if ev.RuleTable != "host_check" || ev.RuleUUID != "VNX-HOST-SSH-ROOT" || ev.Lane != "cis" || ev.Subject != "/etc/ssh/sshd_config" {
		t.Fatalf("event = %+v", ev)
	}
	if a.queue[0].EventKey != a.queue[1].EventKey || a.queue[1].EventKey == a.queue[2].EventKey {
		t.Fatal("the same failure on the same day is one event; the next day is a new one")
	}
}
