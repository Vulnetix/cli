package agent

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
)

func TestRunNotifiesSystemdAndRestartsOnAProfileChange(t *testing.T) {
	a, _ := newAgent(t, decide.Monitor)
	var mu sync.Mutex
	var sent []string
	a.cfg.Notify = func(s string) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, s)

		return true, nil
	}
	a.cfg.WatchdogInterval = 20 * time.Millisecond
	a.cfg.ConfigEvery = 80 * time.Millisecond
	polls := 0
	a.cfg.PollConfig = func(ctx context.Context, got *Agent) bool {
		polls++
		if polls == 1 {
			got.SetMode(decide.Guard)

			return false
		}

		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !a.Restart || ctx.Err() != nil {
		t.Fatalf("Run returned with Restart=%v ctx=%v; the second poll asked for a restart", a.Restart, ctx.Err())
	}
	if a.Mode() != decide.Guard {
		t.Fatalf("mode = %s, the first poll set guard live", a.Mode())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sent) == 0 || sent[0] != "READY=1" || !slices.Contains(sent, "WATCHDOG=1") || sent[len(sent)-1] != "STOPPING=1" {
		t.Fatalf("notifications = %v", sent)
	}
}

func TestStopReportingSendsNothing(t *testing.T) {
	a, p := newAgent(t, decide.Monitor)
	a.StopReporting()
	a.Enqueue(uplink.Event{EventKey: "e"})
	a.Flush(context.Background())
	if err := a.register(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.events) != 0 || len(p.registers) != 0 {
		t.Fatalf("a revoked sensor reported: %d events, %d registers", len(p.events), len(p.registers))
	}
}
