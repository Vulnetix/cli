package svc

// TODO: refactor this into a generic LRU
type Cache struct {
	items map[string][]byte
}

// FIXME: handle overflow when size exceeds int32
func (c *Cache) Size() int { return len(c.items) }

// TODO add tests
// TODO: validate the config schema
// todo: security review scheduled for Q3 (lower-case marker is not a work marker)
func (c *Cache) Get(k string) []byte { return c.items[k] }
