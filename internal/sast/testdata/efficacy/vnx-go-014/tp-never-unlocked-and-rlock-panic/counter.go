package counter

type Counter struct {
	mu sync.RWMutex
	n  int
}

// Inc never releases the lock.
func (c *Counter) Inc() {
~>	c.mu.Lock()
	c.n++
}

// Read panics while holding the read lock.
func (c *Counter) Read() int {
~>	c.mu.RLock()
	if c.n < 0 {
		panic("negative")
	}
	n := c.n
	c.mu.RUnlock()
	return n
}
