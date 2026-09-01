package lsp

import (
	"context"
	"sync"
	"time"
)

// Scheduler decides when analysis runs and makes sure it can be stopped.
//
// Three queues with different policies, because the triggers have genuinely
// different costs and expectations:
//
//	doc        didChange. Debounced, coalesced per URI, cheap rule kinds only,
//	           and structurally unable to touch the network.
//	save       didSave. Immediate, coalesced per URI, adds the expensive kinds.
//	workspace  an explicit scan or a watched-file change. One at a time.
//
// The doc queue is the one users feel. It cancels the in-flight evaluation for
// a URI when a newer change arrives, because the result of analysing text the
// user has already replaced is worth nothing and finishing it delays the answer
// they do want.
type Scheduler struct {
	debounce time.Duration

	mu sync.Mutex
	// pending holds the debounce timer per URI. A new change resets it, which
	// is what turns a burst of keystrokes into one evaluation.
	pending map[string]*time.Timer
	// inflight holds the running evaluation per URI. Keyed by a generation
	// number rather than the cancel func, because Go func values cannot be
	// compared, so there is no other way for a finishing run to ask "am I still
	// the current one, or did a newer change replace me?".
	inflight map[string]*run
	nextGen  uint64
	// workspace is the cancel func for the running workspace scan, of which
	// there is at most one.
	workspaceCancel context.CancelFunc
	workspaceDone   chan struct{}

	closed bool
	wg     sync.WaitGroup
}

// run is one in-flight document evaluation.
type run struct {
	gen    uint64
	cancel context.CancelFunc
}

func NewScheduler(debounce time.Duration) *Scheduler {
	return &Scheduler{
		debounce: debounce,
		pending:  make(map[string]*time.Timer, 8),
		inflight: make(map[string]*run, 8),
	}
}

// ScheduleDocument queues work for a document after the debounce interval.
//
// A newer change for the same URI resets the timer and cancels any evaluation
// already running for it. fn receives a context that is cancelled on either.
func (s *Scheduler) ScheduleDocument(uri string, fn func(context.Context)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}

	// Supersede: the queued run and the running one are both about text that
	// no longer exists.
	if timer, ok := s.pending[uri]; ok {
		timer.Stop()
	}
	if cur, ok := s.inflight[uri]; ok {
		cur.cancel()
		delete(s.inflight, uri)
	}

	if s.debounce <= 0 {
		s.startLocked(uri, fn)
		return
	}

	s.pending[uri] = time.AfterFunc(s.debounce, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return
		}
		delete(s.pending, uri)
		s.startLocked(uri, fn)
	})
}

// RunDocumentNow runs work for a document immediately, cancelling anything
// queued or running for it. This is the save path: the user has committed to
// the text, so waiting out a debounce would only add latency.
func (s *Scheduler) RunDocumentNow(uri string, fn func(context.Context)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if timer, ok := s.pending[uri]; ok {
		timer.Stop()
		delete(s.pending, uri)
	}
	if cur, ok := s.inflight[uri]; ok {
		cur.cancel()
		delete(s.inflight, uri)
	}
	s.startLocked(uri, fn)
}

// startLocked launches fn. Caller holds s.mu.
func (s *Scheduler) startLocked(uri string, fn func(context.Context)) {
	ctx, cancel := context.WithCancel(context.Background())
	s.nextGen++
	cur := &run{gen: s.nextGen, cancel: cancel}
	s.inflight[uri] = cur

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			s.mu.Lock()
			// Clear the entry only if it is still ours. A newer change may have
			// replaced it while this run was finishing, and deleting that
			// would orphan the newer run's cancel func: nothing could stop it
			// afterwards, including Close.
			if got, ok := s.inflight[uri]; ok && got.gen == cur.gen {
				delete(s.inflight, uri)
			}
			s.mu.Unlock()
			cancel()
		}()
		fn(ctx)
	}()
}

// CancelDocument stops queued and running work for a URI, which is what
// didClose does: nobody is looking at the result any more.
func (s *Scheduler) CancelDocument(uri string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if timer, ok := s.pending[uri]; ok {
		timer.Stop()
		delete(s.pending, uri)
	}
	if cur, ok := s.inflight[uri]; ok {
		cur.cancel()
		delete(s.inflight, uri)
	}
}

// RunWorkspace starts a workspace scan, cancelling any scan already running.
//
// At most one at a time. A workspace scan is minutes of work on a large
// repository, and running two concurrently would double memory and halve the
// throughput of both for no benefit.
//
// Returns a channel closed when the scan finishes, so a caller that needs to
// wait can, without the scheduler holding a lock while it does.
func (s *Scheduler) RunWorkspace(fn func(context.Context)) <-chan struct{} {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	if s.workspaceCancel != nil {
		s.workspaceCancel()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.workspaceCancel = cancel
	s.workspaceDone = done
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer close(done)
		defer func() {
			s.mu.Lock()
			if s.workspaceDone == done {
				s.workspaceCancel = nil
				s.workspaceDone = nil
			}
			s.mu.Unlock()
			cancel()
		}()
		fn(ctx)
	}()

	return done
}

// CancelWorkspace stops the running workspace scan, if any.
func (s *Scheduler) CancelWorkspace() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.workspaceCancel != nil {
		s.workspaceCancel()
	}
}

// WorkspaceRunning reports whether a workspace scan is in flight.
func (s *Scheduler) WorkspaceRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.workspaceCancel != nil
}

// Close cancels everything and waits for it to stop.
//
// Called on shutdown. Without the wait, the process can exit while an
// evaluation is mid-write to the connection, which the client sees as a
// truncated message rather than a clean shutdown.
func (s *Scheduler) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	for uri, timer := range s.pending {
		timer.Stop()
		delete(s.pending, uri)
	}
	for uri, cur := range s.inflight {
		cur.cancel()
		delete(s.inflight, uri)
	}
	if s.workspaceCancel != nil {
		s.workspaceCancel()
	}
	s.mu.Unlock()

	s.wg.Wait()
}

// SetDebounce changes the quiet period for subsequent scheduling.
//
// Timers already pending keep the interval they were created with. Rescheduling
// them would restart the clock for a change the user has already finished
// making, which is the opposite of what a shorter debounce was asked for.
func (s *Scheduler) SetDebounce(d time.Duration) {
	if d < 0 {
		return
	}
	s.mu.Lock()
	s.debounce = d
	s.mu.Unlock()
}
