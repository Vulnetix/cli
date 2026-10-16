package store

import "sync"

type Store struct {
	mu    sync.Mutex
	items []string
}

func (s *Store) Add(x string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, x)
	s.count()
}

func (s *Store) Reset() {
	s.mu.Lock()
	s.items = nil
~>	s.mu.Lock()
	s.mu.Unlock()
}
