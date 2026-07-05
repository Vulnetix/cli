package cmd

import (
	"sync"
	"testing"
	"time"
)

// TestUpdateAdvisoryConcurrentInvocations reproduces the historical
// "send on closed channel" panic: cobra.OnInitialize fires startupHooks once
// per Execute, so a process running many commands (the test binary itself)
// repeatedly reassigns updateCheckResult while prior background goroutines and
// the PostRun consumer still touch it. The pre-fix code had each goroutine
// close/send the shared package var, so one goroutine could close another's
// channel. Each invocation now owns its own channel, so this must run cleanly
// (and race-clean under `go test -race`).
func TestUpdateAdvisoryConcurrentInvocations(t *testing.T) {
	const workers = 300
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			// Half the invocations produce an advisory, half don't — exercising
			// both the send and the close-only paths.
			startUpdateAdvisory(func() (string, bool) {
				return "update available", i%2 == 0
			})
			// Concurrently consume, as PersistentPostRun / vdb.go do.
			_ = consumeUpdateAdvisory()
		}(i)
	}
	wg.Wait()
	// Drain whatever the last invocation left, exercising the consumer once more.
	_ = consumeUpdateAdvisory()
}

// TestUpdateAdvisoryDelivery verifies a produced message is delivered exactly
// once and that a subsequent read returns empty (channel drained/closed).
func TestUpdateAdvisoryDelivery(t *testing.T) {
	startUpdateAdvisory(func() (string, bool) {
		return "hello", true
	})
	// The background goroutine may not have sent yet; poll with a yield until
	// the message arrives or a deadline elapses. (consumeUpdateAdvisory is
	// non-blocking by contract, so the test does the waiting.)
	var got string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if msg := consumeUpdateAdvisory(); msg != "" {
			got = msg
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got != "hello" {
		t.Fatalf("expected advisory %q to be delivered, got %q", "hello", got)
	}
	// After consumption the buffered value is gone; a further read is empty.
	if msg := consumeUpdateAdvisory(); msg != "" {
		t.Errorf("expected no further advisory, got %q", msg)
	}
}

// TestConsumeUpdateAdvisoryNilChannel confirms the consumer is safe before any
// advisory channel has been installed.
func TestConsumeUpdateAdvisoryNilChannel(t *testing.T) {
	updateCheckMu.Lock()
	updateCheckResult = nil
	updateCheckMu.Unlock()
	if msg := consumeUpdateAdvisory(); msg != "" {
		t.Errorf("expected empty advisory for nil channel, got %q", msg)
	}
}
