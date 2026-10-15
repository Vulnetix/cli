package store

import "sync"

type Store struct{ mu sync.Mutex }

func (s *Store) Try() bool {
	if ok := s.mu.TryLock(); !ok {
		return false
	}
	s.mu.Unlock()
	locked := s.mu.TryLock()
	if locked {
		s.mu.Unlock()
	}
	for !s.mu.TryLock() {
	}
	s.mu.Unlock()
	return s.mu.TryLock()
}
