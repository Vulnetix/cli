package queue

import "sync"

type R struct {
	mu sync.RWMutex
	n  int
}

func (r *R) Get() int {
	r.mu.RLock()
	v := r.n
	r.mu.RUnlock()
~>	r.mu.RUnlock()
	return v
}
