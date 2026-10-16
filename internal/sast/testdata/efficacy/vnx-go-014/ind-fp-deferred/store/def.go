package store

import "sync"

type S struct {
	mu sync.Mutex
	m  map[string]int
}

func (s *S) Get(k string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	if !ok {
		return 0, ErrMissing
	}
	return v, nil
}
