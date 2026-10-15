package stats

import "sync"

type Counter struct {
	sync.Mutex
	hits map[string]int
}

func (c *Counter) Inc(name string) {
	c.Lock()
	defer c.Unlock()
	if c.hits == nil {
		c.hits = map[string]int{}
	}
	c.hits[name]++
	if c.hits[name] > 1000 {
~>		c.Lock()
		c.hits = map[string]int{}
	}
}
