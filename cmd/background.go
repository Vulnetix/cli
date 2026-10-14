package cmd

import (
	"bytes"
	"io"
	"sync"
)

// Background work is a request whose answer the scan never reads: the raw
// manifest bodies archived under the snapshot, the reachability evidence, the
// graph insights. The scan used to wait for each in turn before doing anything
// else, which put a round trip per request on every run. They now start as soon
// as their inputs exist and are joined once, by waitBackground, before the
// command returns, so the process never exits with a request in flight.
//
// A background task writes to its own buffer, flushed at the join, so its
// output never interleaves with the progress display or the report.

var (
	backgroundMu    sync.Mutex
	backgroundWG    sync.WaitGroup
	backgroundOut   []*bytes.Buffer
	backgroundSinks []io.Writer
)

// goBackground runs fn concurrently. Whatever fn writes to its writer reaches w
// when waitBackground joins it.
func goBackground(w io.Writer, fn func(w io.Writer)) {
	buf := &bytes.Buffer{}
	backgroundMu.Lock()
	backgroundOut = append(backgroundOut, buf)
	backgroundSinks = append(backgroundSinks, w)
	backgroundMu.Unlock()

	backgroundWG.Add(1)
	go func() {
		defer backgroundWG.Done()
		fn(buf)
	}()
}

// waitBackground blocks until every background task has finished and writes
// their output, in the order the tasks started.
func waitBackground() {
	backgroundWG.Wait()
	backgroundMu.Lock()
	out, sinks := backgroundOut, backgroundSinks
	backgroundOut, backgroundSinks = nil, nil
	backgroundMu.Unlock()
	for i, buf := range out {
		if buf.Len() > 0 && sinks[i] != nil {
			_, _ = sinks[i].Write(buf.Bytes())
		}
	}
}

// future is a value computed concurrently and read once it is ready.
type future[T any] struct {
	done chan struct{}
	val  T
}

func startFuture[T any](fn func() T) *future[T] {
	f := &future[T]{done: make(chan struct{})}
	go func() {
		defer close(f.done)
		f.val = fn()
	}()
	return f
}

// get waits for the value. A nil future yields the zero value.
func (f *future[T]) get() T {
	var zero T
	if f == nil {
		return zero
	}
	<-f.done
	return f.val
}
