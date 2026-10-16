package cache

// TODO: refactor eviction into its own type once the benchmarks settle.
// FIXME: this allocates on every Get; reuse the node pool.
func (c *LRU) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.items[key]
	if !ok {
		return nil, false
	}
	c.moveToFront(n)
	return n.value, true
}
