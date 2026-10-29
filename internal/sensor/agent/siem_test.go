package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/proxy"
	"github.com/vulnetix/cli/v3/internal/sensor/siem"
)

func TestNewWiresTheEgressProxyToTheSIEM(t *testing.T) {
	fwd := &siem.Forwarder{Token: "gdn_test"}
	egress := &proxy.Egress{}
	New(Config{Mode: decide.Monitor, Egress: egress, EgressListen: "127.0.0.1:0", SIEM: fwd})
	if egress.Observe == nil {
		t.Fatal("the egress proxy is not observed")
	}
	egress.Observe(siem.EgressDecision{Time: time.Now(), Target: "example.com:443"})
	if fwd.Pending() != 1 {
		t.Fatal("an observed connection did not reach the forwarder")
	}

	plain := &proxy.Egress{}
	New(Config{Mode: decide.Monitor, Egress: plain, EgressListen: "127.0.0.1:0"})
	if plain.Observe != nil {
		t.Fatal("without --forward siem nothing is observed")
	}
}

// What the forwarder holds when the sensor stops is sent before Run returns.
func TestRunFlushesTheSIEMOnShutdown(t *testing.T) {
	var mu sync.Mutex
	var events int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Events []json.RawMessage `json:"events"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		events += len(body.Events)
		mu.Unlock()
	}))
	defer srv.Close()
	fwd := &siem.Forwarder{URL: srv.URL, Token: "gdn_test", FlushEvery: time.Hour, Logf: t.Logf}
	a := New(Config{Mode: decide.Monitor, SIEM: fwd, DNSListen: "127.0.0.1:0", Logf: t.Logf})
	fwd.DNS(siem.DNSDecision{Time: time.Now(), QName: "example.com"})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return")
	}
	mu.Lock()
	defer mu.Unlock()
	if events != 1 {
		t.Fatalf("events sent at shutdown = %d, want 1", events)
	}
}
