package pool

import "sync"

type Pool struct {
	mu   sync.Mutex
	free []int
}

func (p *Pool) Take() (int, bool) {
	if !p.mu.TryLock() {
		return 0, false
	}
	defer p.mu.Unlock()
	n := p.free[len(p.free)-1]
	p.free = p.free[:len(p.free)-1]
	return n, true
}

func (p *Pool) Busy() bool {
	ok := p.mu.TryLock()
	if ok {
		p.mu.Unlock()
	}
	_ = p.mu.TryLock()
	return !ok
}

func (p *Pool) tryHold() bool {
	return p.mu.TryLock()
}

func (p *Pool) Put(n int) {
	p.mu.Lock()
	p.free = append(p.free, n)
	p.mu.Unlock()
}
