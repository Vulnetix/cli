package store

type Store struct {
	mu sync.RWMutex
	m  map[string]int
}

// Deferred immediately.
func (s *Store) Get(k string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[k]
}

// Deferred after a comment and a blank line.
func (s *Store) Set(k string, v int) {
	s.mu.Lock()
	// the map is shared with the reaper

	defer s.mu.Unlock()
	s.m[k] = v
}

// A short critical section with nothing that can exit in between.
func (s *Store) Len() int {
	s.mu.RLock()
	n := len(s.m)
	s.mu.RUnlock()
	return n
}

// Unlocked on the early path before returning.
func (s *Store) Take(k string) (int, bool) {
	s.mu.Lock()
	v, ok := s.m[k]
	if !ok {
		s.mu.Unlock()
		return 0, false
	}
	delete(s.m, k)
	s.mu.Unlock()
	return v, true
}

// The release is in a deferred closure.
func (s *Store) Reset() {
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
	}()
	s.m = map[string]int{}
}

// A wrapper whose caller owns the Unlock.
func (s *Store) Lock() {
	s.mu.Lock()
}

// s.mu.Lock() in a comment is not a lock.
