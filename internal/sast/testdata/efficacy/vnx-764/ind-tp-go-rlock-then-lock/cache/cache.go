package cache

import "sync"

type Cache struct {
	mu sync.RWMutex
	m  map[string]string
}

func (s *Cache) Get(k string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[k]
	if !ok {
~>		s.mu.Lock()
		s.m[k] = "x"
		s.mu.Unlock()
	}
	return v
}
