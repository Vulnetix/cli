package store

import "sync"

type Counter struct {
	mu sync.RWMutex
	n  map[string]int
}

func (c *Counter) Inc(k string) {
	c.mu.Lock()
	c.n[k]++
	c.mu.Unlock()
}

func (c *Counter) Read(k string) int {
	c.mu.RLock()
	v := c.n[k]
	c.mu.RUnlock()
	return v
}
