package store

import "errors"

var errMissing = errors.New("missing")

type Store struct {
	mu sync.Mutex
	m  map[string]int
}

// Get leaks the lock on the miss path: the return runs before Unlock.
func (s *Store) Get(k string) (int, error) {
~>	s.mu.Lock()
	v, ok := s.m[k]
	if !ok {
		return 0, errMissing
	}
	s.mu.Unlock()
	return v, nil
}
