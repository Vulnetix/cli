package store

import "sync"

type Store struct {
	mu   sync.Mutex
	data map[string]string
}

func (s *Store) Set(key, value string) error {
~>	s.mu.Lock()
	if key == "" {
		return ErrEmptyKey
	}
	s.data[key] = value
	s.mu.Unlock()
	return nil
}
