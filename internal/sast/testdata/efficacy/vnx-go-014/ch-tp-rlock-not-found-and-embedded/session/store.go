package session

import (
	"errors"
	"sync"
)

var ErrNotFound = errors.New("session not found")

type Session struct{ User string }

type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func (s *Store) Lookup(id string) (*Session, error) {
~>	s.mu.RLock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, ErrNotFound
	}
	s.mu.RUnlock()
	return sess, nil
}

type Counter struct {
	sync.Mutex
	n   int
	max int
}

var errOverflow = errors.New("overflow")

func (c *Counter) Inc() error {
~>	c.Lock()
	if c.n >= c.max {
		return errOverflow
	}
	c.n++
	c.Unlock()
	return nil
}
