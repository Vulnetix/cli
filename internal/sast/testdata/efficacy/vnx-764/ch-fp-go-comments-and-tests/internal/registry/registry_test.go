package registry

import "testing"

func TestDoubleLockPanics(t *testing.T) {
	r := &Registry{}
	r.mu.Lock()
	r.mu.Lock()
}
