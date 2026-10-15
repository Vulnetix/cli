package store

func (s *Store) Run(fast bool) {
	if fast {
		s.mu.Lock()
	} else {
		s.mu.Lock()
	}
	s.mu.Unlock()
}

func (s *Store) Spawn() {
	s.mu.Lock()
	go func() {
		s.mu.Lock()
		s.n++
		s.mu.Unlock()
	}()
	s.mu.Unlock()
}

func (s *Store) Loop(items []int) {
	for _, it := range items {
		s.mu.Lock()
		s.n += it
		s.mu.Unlock()
	}
}
