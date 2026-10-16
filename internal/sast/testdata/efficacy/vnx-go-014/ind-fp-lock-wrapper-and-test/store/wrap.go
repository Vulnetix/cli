package store

import "sync"

type Guard struct {
	mu sync.Mutex
}

// Lock is a wrapper; the caller owns the unlock.
func (g *Guard) Lock() {
	g.mu.Lock()
}

func (g *Guard) Unlock() {
	g.mu.Unlock()
}
