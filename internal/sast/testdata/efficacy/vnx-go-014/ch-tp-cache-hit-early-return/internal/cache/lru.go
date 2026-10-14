package cache

import (
	"container/list"
	"sync"
)

type entry struct {
	key string
	val []byte
}

type LRU struct {
	mu    sync.Mutex
	ll    *list.List
	items map[string]*list.Element
	cap   int
}

func (c *LRU) Get(key string) ([]byte, bool) {
~>	c.mu.Lock()
	if el, ok := c.items[key]; ok {
		c.ll.MoveToFront(el)
		return el.Value.(*entry).val, true
	}
	c.mu.Unlock()
	return nil, false
}

func (c *LRU) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
