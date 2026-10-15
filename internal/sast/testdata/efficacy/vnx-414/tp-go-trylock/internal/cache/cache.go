package cache

import "sync"

type Cache struct {
	mu   sync.Mutex
	rw   sync.RWMutex
	data map[string]string
}

func (c *Cache) Set(k, v string) {
~>	c.mu.TryLock()
	c.data[k] = v
	c.mu.Unlock()
}

func (c *Cache) Get(k string) string {
~>	c.rw.TryRLock() // best effort
	defer c.rw.RUnlock()
	return c.data[k]
}
