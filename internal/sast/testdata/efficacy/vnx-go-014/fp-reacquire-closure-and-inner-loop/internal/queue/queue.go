package queue

import (
	"context"
	"sync"
)

type Queue struct {
	mu        sync.Mutex
	items     []string
	listeners map[int]func(string)
	done      chan struct{}
}

// Wait releases the lock while blocked and takes it back for the caller,
// like sync.Cond.Wait.
func (q *Queue) Wait() {
	ch := q.done
	q.mu.Unlock()
	<-ch
	q.mu.Lock()
}

// Drain holds the lock for the whole call; the early return happens after a
// deferred Unlock is in place.
func (q *Queue) Drain() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return nil
	}
	out := q.items
	q.items = nil
	return out
}

// Listen registers a callback; the returns belong to the func literal.
func (q *Queue) Listen(ctx context.Context, id int, fn func(string)) {
	q.mu.Lock()
	q.listeners[id] = func(s string) {
		if ctx.Err() != nil {
			return
		}
		fn(s)
	}
	q.mu.Unlock()
}

// Compact's continue belongs to the loop inside the critical section.
func (q *Queue) Compact() {
	q.mu.Lock()
	kept := q.items[:0]
	for _, it := range q.items {
		if it == "" {
			continue
		}
		kept = append(kept, it)
	}
	q.items = kept
	q.mu.Unlock()
}
