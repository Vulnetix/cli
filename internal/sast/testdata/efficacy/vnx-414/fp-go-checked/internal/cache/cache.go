package cache

func (c *Cache) Set(k, v string) bool {
	if !c.mu.TryLock() {
		return false
	}
	defer c.mu.Unlock()
	c.data[k] = v
	ok := c.rw.TryRLock()
	_ = c.other.TryLock()
	c.mu.Lock()
	return ok
}
