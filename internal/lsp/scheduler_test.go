package lsp

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// eventually polls until cond holds or the deadline passes, so timing tests do
// not depend on a fixed sleep being long enough on a loaded CI machine.
func eventually(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("condition never held: %s", msg)
}

func TestDebounceCoalescesABurst(t *testing.T) {
	// The point of the debounce: typing produces a burst of didChange, and the
	// user wants one evaluation of the final text, not one per keystroke.
	//
	// "One burst" is a claim about wall-clock time, and this test is the only
	// one here that needs the machine to keep a promise about it: the ten
	// changes have to land inside a single debounce window or the extra
	// evaluations are correct behaviour, not a bug. A shared CI runner under
	// -race can stall a 2ms sleep well past 30ms, which is how this test came
	// to report actual:3 and actual:10 on two different runs of unchanged
	// scheduler code.
	//
	// So the burst is timed and the premise is checked rather than assumed. A
	// burst that overran the window says nothing about coalescing, and is
	// retried instead of being judged.
	const debounce = 200 * time.Millisecond
	const attempts = 5

	for attempt := 1; attempt <= attempts; attempt++ {
		s := NewScheduler(debounce)

		var runs atomic.Int64
		start := time.Now()
		for range 10 {
			s.ScheduleDocument("file:///a.go", func(context.Context) { runs.Add(1) })
			time.Sleep(2 * time.Millisecond)
		}
		// The whole burst fitting inside one window is stronger than needed
		// and much simpler to state: it means no individual gap reached the
		// debounce, so no timer can have fired part-way through.
		burst := time.Since(start)

		eventually(t, 5*time.Second, func() bool { return runs.Load() >= 1 }, "the run should eventually happen")
		time.Sleep(2 * debounce)
		got := runs.Load()
		s.Close()

		if burst >= debounce {
			t.Logf("attempt %d/%d: the ten changes took %v, longer than the %v debounce, so they were never one burst; retrying", attempt, attempts, burst, debounce)
			continue
		}

		require.Equal(t, int64(1), got, "ten changes in one burst must produce exactly one evaluation")
		return
	}

	t.Skipf("no burst of ten changes fit inside %v in %d attempts; this machine is too loaded to ask the question", debounce, attempts)
}

func TestDebounceRunsAgainAfterAQuietPeriod(t *testing.T) {
	s := NewScheduler(20 * time.Millisecond)
	defer s.Close()

	var runs atomic.Int64
	fn := func(context.Context) { runs.Add(1) }

	s.ScheduleDocument("file:///a.go", fn)
	eventually(t, time.Second, func() bool { return runs.Load() == 1 }, "first run")

	s.ScheduleDocument("file:///a.go", fn)
	eventually(t, time.Second, func() bool { return runs.Load() == 2 }, "second run after a gap")
}

func TestNewChangeCancelsTheRunningEvaluation(t *testing.T) {
	// Finishing an evaluation of text the user has already replaced delays the
	// answer they actually want, so the in-flight run is cancelled.
	s := NewScheduler(0)
	defer s.Close()

	started := make(chan struct{})
	var cancelled atomic.Bool

	s.ScheduleDocument("file:///a.go", func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		cancelled.Store(true)
	})
	<-started

	s.ScheduleDocument("file:///a.go", func(context.Context) {})
	eventually(t, time.Second, cancelled.Load, "the superseded run must be cancelled")
}

func TestDifferentDocumentsDoNotCancelEachOther(t *testing.T) {
	// Coalescing is per URI. Editing one file must not stop analysis of another
	// that the user also has open.
	s := NewScheduler(0)
	defer s.Close()

	var aCancelled atomic.Bool
	aStarted := make(chan struct{})

	s.ScheduleDocument("file:///a.go", func(ctx context.Context) {
		close(aStarted)
		select {
		case <-ctx.Done():
			aCancelled.Store(true)
		case <-time.After(200 * time.Millisecond):
		}
	})
	<-aStarted

	s.ScheduleDocument("file:///b.go", func(context.Context) {})
	time.Sleep(50 * time.Millisecond)
	require.False(t, aCancelled.Load(), "a change to b.go must not cancel analysis of a.go")
}

func TestRunDocumentNowSkipsTheDebounce(t *testing.T) {
	// The save path: the user has committed to the text, so waiting out a
	// debounce would be latency with no benefit.
	s := NewScheduler(10 * time.Second)
	defer s.Close()

	ran := make(chan struct{})
	s.RunDocumentNow("file:///a.go", func(context.Context) { close(ran) })

	select {
	case <-ran:
	case <-time.After(time.Second):
		t.Fatal("RunDocumentNow waited for the debounce")
	}
}

func TestRunDocumentNowSupersedesAPendingDebounce(t *testing.T) {
	s := NewScheduler(50 * time.Millisecond)
	defer s.Close()

	var debounced, immediate atomic.Int64
	s.ScheduleDocument("file:///a.go", func(context.Context) { debounced.Add(1) })
	s.RunDocumentNow("file:///a.go", func(context.Context) { immediate.Add(1) })

	eventually(t, time.Second, func() bool { return immediate.Load() == 1 }, "the save run")
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, int64(0), debounced.Load(), "the queued keystroke run must be dropped, not run afterwards")
}

func TestCancelDocumentStopsQueuedAndRunningWork(t *testing.T) {
	s := NewScheduler(50 * time.Millisecond)
	defer s.Close()

	var ran atomic.Int64
	s.ScheduleDocument("file:///a.go", func(context.Context) { ran.Add(1) })
	s.CancelDocument("file:///a.go")

	time.Sleep(120 * time.Millisecond)
	require.Equal(t, int64(0), ran.Load(), "closing a document must drop its queued analysis")
}

func TestWorkspaceScansAreSerialised(t *testing.T) {
	// Two concurrent workspace scans double memory and halve throughput for no
	// benefit, so a new one supersedes rather than joins.
	s := NewScheduler(0)
	defer s.Close()

	firstStarted := make(chan struct{})
	var firstCancelled atomic.Bool

	s.RunWorkspace(func(ctx context.Context) {
		close(firstStarted)
		<-ctx.Done()
		firstCancelled.Store(true)
	})
	<-firstStarted

	done := s.RunWorkspace(func(context.Context) {})
	<-done

	eventually(t, time.Second, firstCancelled.Load, "the first workspace scan must be cancelled by the second")
}

func TestRunWorkspaceReportsCompletion(t *testing.T) {
	s := NewScheduler(0)
	defer s.Close()

	done := s.RunWorkspace(func(context.Context) { time.Sleep(10 * time.Millisecond) })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the done channel was never closed")
	}
	require.False(t, s.WorkspaceRunning(), "state must be cleared once the scan finishes")
}

func TestCancelWorkspace(t *testing.T) {
	s := NewScheduler(0)
	defer s.Close()

	started := make(chan struct{})
	var cancelled atomic.Bool
	done := s.RunWorkspace(func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		cancelled.Store(true)
	})
	<-started

	require.True(t, s.WorkspaceRunning())
	s.CancelWorkspace()
	<-done
	require.True(t, cancelled.Load())
}

func TestCloseCancelsAndWaits(t *testing.T) {
	// Exiting while an evaluation is mid-write to the connection shows up at
	// the client as a truncated message rather than a clean shutdown.
	s := NewScheduler(0)

	var finished atomic.Bool
	started := make(chan struct{})
	s.ScheduleDocument("file:///a.go", func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		time.Sleep(20 * time.Millisecond)
		finished.Store(true)
	})
	<-started

	s.Close()
	require.True(t, finished.Load(), "Close must wait for in-flight work to return")
}

func TestScheduleAfterCloseIsIgnored(t *testing.T) {
	s := NewScheduler(0)
	s.Close()

	var ran atomic.Int64
	s.ScheduleDocument("file:///a.go", func(context.Context) { ran.Add(1) })
	s.RunDocumentNow("file:///b.go", func(context.Context) { ran.Add(1) })
	<-s.RunWorkspace(func(context.Context) { ran.Add(1) })

	time.Sleep(30 * time.Millisecond)
	require.Equal(t, int64(0), ran.Load(), "work scheduled after shutdown must not start")
}

func TestCloseIsIdempotent(t *testing.T) {
	s := NewScheduler(0)
	require.NotPanics(t, func() {
		s.Close()
		s.Close()
	})
}

func TestSchedulerUnderConcurrentUse(t *testing.T) {
	// The read loop schedules while scan goroutines finish and clear their
	// entries. Run with -race.
	s := NewScheduler(time.Millisecond)
	defer s.Close()

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			uri := "file:///f" + string(rune('a'+i%5)) + ".go"
			for range 20 {
				s.ScheduleDocument(uri, func(context.Context) {})
				s.RunDocumentNow(uri, func(context.Context) {})
				s.CancelDocument(uri)
			}
		}(i)
	}
	wg.Wait()
}

func TestInflightEntriesDoNotLeak(t *testing.T) {
	// A finishing run must clear its own entry, and only its own: deleting a
	// newer run's entry would orphan its cancel func, so nothing could stop it
	// afterwards, including Close.
	s := NewScheduler(0)
	defer s.Close()

	for range 50 {
		s.RunDocumentNow("file:///a.go", func(context.Context) {})
	}

	eventually(t, time.Second, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.inflight) == 0
	}, "in-flight entries should be cleared once runs finish")
}
