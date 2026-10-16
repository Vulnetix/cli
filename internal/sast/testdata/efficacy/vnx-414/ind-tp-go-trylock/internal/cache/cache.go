package cache

import "sync"

type Store struct {
	rw    sync.RWMutex
	mu    sync.Mutex
	items map[string][]byte
	hits  int
}

func (s *Store) Get(k string) []byte {
~>	s.rw.TryRLock()
	defer s.rw.RUnlock()
	return s.items[k]
}

func (s *Store) Put(k string, v []byte) {
~>	s.mu.TryLock()
	s.items[k] = v
	s.mu.Unlock()
}
