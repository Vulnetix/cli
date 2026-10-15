package store

import "sync"

type Store struct {
	mu    sync.Mutex
	other sync.Mutex
	n     int
}

func (s *Store) A() {
	s.mu.Lock()
	s.n++
	s.mu.Unlock()
	s.mu.Lock()
	s.n--
	s.mu.Unlock()
}

func (s *Store) B() {
	s.mu.Lock()
	s.other.Lock()
	s.other.Unlock()
	s.mu.Unlock()
}

func (s *Store) Wait(c *sync.Cond) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.n == 0 {
		s.mu.Unlock()
		wait()
		s.mu.Lock()
	}
}
