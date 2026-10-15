package cache

import "sync"

type Cache struct {
	mu    sync.RWMutex
	items map[string]string
}

func (c *Cache) GetOrLoad(k string, load func() string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if v, ok := c.items[k]; ok {
		return v
	}
	v := load()
~>	c.mu.Lock()
	c.items[k] = v
	c.mu.Unlock()
	return v
}
