package queue

import (
	"sync"
	"testing"
)

func TestDoubleUnlock(t *testing.T) {
	var mu sync.Mutex
	mu.Lock()
	defer mu.Unlock()
	mu.Unlock()
}
