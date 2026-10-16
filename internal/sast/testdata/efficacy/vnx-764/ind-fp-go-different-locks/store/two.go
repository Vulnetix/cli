package store

import "sync"

type Two struct {
	a sync.Mutex
	b sync.Mutex
}

func (t *Two) Both() {
	t.a.Lock()
	defer t.a.Unlock()
	t.b.Lock()
	defer t.b.Unlock()
}
