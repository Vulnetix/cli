package cache

import "sync"

type Cache struct {
	mu    sync.RWMutex
	items map[string][]byte
}

func (c *Cache) Peek(k string) []byte {
~>	c.mu.RLock()
	v := c.items[k]
	return v
}
