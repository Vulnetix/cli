package store

import "sync"

type Store struct {
	mu sync.RWMutex
	m  map[string]int
}

func (s *Store) Inc(k string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[k]; !ok {
~>		s.mu.Lock()
		s.m[k] = 0
	}
	s.m[k]++
}

func (s *Store) GetOrInit(k string) int {
	s.mu.RLock()
	v, ok := s.m[k]
	if !ok {
~>		s.mu.Lock()
		s.m[k] = 1
		s.mu.Unlock()
	}
	s.mu.RUnlock()
	return v
}

func (s *Store) Sum() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for k := range s.m {
~>		s.mu.RLock()
		n += s.m[k]
		s.mu.RUnlock()
	}
	return n
}
