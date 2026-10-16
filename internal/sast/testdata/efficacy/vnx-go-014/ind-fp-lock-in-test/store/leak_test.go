package store

import (
	"sync"
	"testing"
)

func TestHeld(t *testing.T) {
	var mu sync.Mutex
	mu.Lock()
	if testing.Short() {
		t.Skip("short")
	}
	mu.Unlock()
}
