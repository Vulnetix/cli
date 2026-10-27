package cmd

import (
	"bytes"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

func TestBackgroundOutputIsHeldUntilJoinAndKeepsStartOrder(t *testing.T) {
	var out bytes.Buffer
	var finished atomic.Int32
	release := make(chan struct{})
	goBackground(&out, func(w io.Writer) {
		<-release // the first task finishes last
		fmt.Fprintln(w, "first")
		finished.Add(1)
	})
	goBackground(&out, func(w io.Writer) {
		fmt.Fprintln(w, "second")
		finished.Add(1)
	})
	time.Sleep(10 * time.Millisecond)
	if out.Len() != 0 {
		t.Fatalf("background output reached the writer before the join: %q", out.String())
	}
	close(release)
	waitBackground()
	if finished.Load() != 2 {
		t.Fatal("waitBackground returned before every task finished")
	}
	if got := out.String(); got != "first\nsecond\n" {
		t.Fatalf("output %q, want the tasks' output in the order they started", got)
	}
	waitBackground() // a second join with nothing pending is a no-op
}

func TestFutureIsComputedOnceAndNilIsZero(t *testing.T) {
	var calls atomic.Int32
	f := startFuture(func() int { calls.Add(1); return 42 })
	first, second := f.get(), f.get()
	if first != 42 || second != 42 || calls.Load() != 1 {
		t.Fatalf("future recomputed or lost its value (calls=%d)", calls.Load())
	}
	var nilFuture *future[[]string]
	if nilFuture.get() != nil {
		t.Fatal("a nil future must yield the zero value")
	}
}
