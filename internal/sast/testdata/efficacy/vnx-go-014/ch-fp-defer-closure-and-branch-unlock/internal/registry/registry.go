package registry

import (
	"errors"
	"sync"
)

type Registry struct {
	mu    sync.RWMutex
	items map[string]int
}

func (r *Registry) Put(k string, v int) error {
	r.mu.Lock()
	defer func() {
		r.mu.Unlock()
	}()
	if k == "" {
		return errors.New("empty key")
	}
	r.items[k] = v
	return nil
}

func (r *Registry) Take(k string) (int, error) {
	r.mu.Lock()
	v, ok := r.items[k]
	if !ok {
		r.mu.Unlock()
		return 0, errors.New("missing")
	}
	delete(r.items, k)
	r.mu.Unlock()
	return v, nil
}

func (r *Registry) Snapshot() map[string]int {
	r.mu.RLock()
	out := make(map[string]int, len(r.items))
	for k, v := range r.items {
		out[k] = v
	}
	r.mu.RUnlock()
	if len(out) == 0 {
		return nil
	}
	return out
}
