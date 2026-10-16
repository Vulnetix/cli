package cache

import "testing"

func TestTryLockContention(t *testing.T) {
	s := &Store{items: map[string][]byte{}}
	s.mu.TryLock()
	s.items["k"] = nil
	s.mu.Unlock()
}
