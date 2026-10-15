package store

import (
	"errors"
	"sync"
)

type Store struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func (s *Store) Read(k string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[k]
	if !ok {
~>		s.mu.RUnlock()
		return nil, errors.New("not found")
	}
	return v, nil
}

func (s *Store) Drop(k string) {
	s.mu.Lock()
	delete(s.data, k)
	s.mu.Unlock()
	notify(k)
~>	s.mu.Unlock()
}

func notify(string) {}
