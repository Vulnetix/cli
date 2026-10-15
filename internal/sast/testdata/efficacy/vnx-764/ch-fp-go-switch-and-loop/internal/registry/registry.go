package registry

import "sync"

type Registry struct {
	mu     sync.RWMutex
	byName map[string]int
	shards []*shard
}

type shard struct {
	mu sync.Mutex
	n  int
}

func (r *Registry) Do(write bool, k string) int {
	switch {
	case !write:
		r.mu.RLock()
		defer r.mu.RUnlock()
		return r.byName[k]
	default:
		r.mu.Lock()
		defer r.mu.Unlock()
		r.byName[k]++
		return r.byName[k]
	}
}

func (r *Registry) Reset() {
	for _, s := range r.shards {
		s.mu.Lock()
		s.n = 0
		s.mu.Unlock()
	}
	r.mu.Lock()
	r.byName = map[string]int{}
	r.mu.Unlock()
	r.mu.Lock()
	r.shards = nil
	r.mu.Unlock()
}

func (r *Registry) Async() {
	r.mu.Lock()
	defer r.mu.Unlock()
	go func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.byName = nil
	}()
}
