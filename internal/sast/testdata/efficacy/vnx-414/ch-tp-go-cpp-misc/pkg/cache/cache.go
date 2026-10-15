package cache

import "sync"

type Cache struct {
	mu    sync.RWMutex
	items map[string]string
}

func (c *Cache) Peek(k string) string {
~>	c.mu.TryRLock()
	v := c.items[k]
	c.mu.RUnlock()
	return v
}
