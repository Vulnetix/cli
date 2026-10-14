package jobs

import (
	"log"
	"sync"
)

type Runner struct {
	mu      sync.Mutex
	running map[string]bool
}

func (r *Runner) Start(id string, fn func() error) error {
	defer func() {
		if p := recover(); p != nil {
			log.Printf("job %s panicked: %v", id, p)
		}
	}()
~>	r.mu.Lock()
	if r.running[id] {
		return nil
	}
	if err := fn(); err != nil {
		r.mu.Unlock()
		return err
	}
	r.running[id] = true
	r.mu.Unlock()
	return nil
}

func (r *Runner) Stop(id string) {
	r.mu.Lock()
	unlocked := false
	defer func() {
		if !unlocked {
			r.mu.Unlock()
		}
	}()
	if !r.running[id] {
		return
	}
	delete(r.running, id)
	r.mu.Unlock()
	unlocked = true
}
