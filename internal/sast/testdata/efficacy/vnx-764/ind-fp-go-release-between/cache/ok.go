package cache

import "sync"

type Cache struct {
	mu sync.RWMutex
	m  map[string]string
}

func (s *Cache) Get(k string) string {
	s.mu.RLock()
	v, ok := s.m[k]
	s.mu.RUnlock()
	if !ok {
		s.mu.Lock()
		s.m[k] = "x"
		s.mu.Unlock()
	}
	return v
}

func (s *Cache) Branch(a bool) {
	if a {
		s.mu.Lock()
		s.mu.Unlock()
	} else {
		s.mu.Lock()
		s.mu.Unlock()
	}
}

func (s *Cache) Async() {
	s.mu.Lock()
	go func() {
		s.mu.Lock()
		s.mu.Unlock()
	}()
	s.mu.Unlock()
}
