package cache

import (
	"sync"
	"testing"
)

func TestSelfDeadlock(t *testing.T) {
	var mu sync.Mutex
	mu.Lock()
	mu.Lock()
}
