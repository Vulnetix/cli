package lock

import (
	"errors"
	"log"
	"sync"

	"github.com/gofrs/flock"
)

var ErrBusy = errors.New("busy")

type Job struct {
	mu sync.Mutex
	fl *flock.Flock
}

func (j *Job) Run() error {
	if !j.mu.TryLock() {
		return ErrBusy
	}
	defer j.mu.Unlock()
	if err := j.fl.Lock(); err != nil {
		return err
	}
	defer j.fl.Unlock()
	log.Println("mu.Lock() held while running; return early is safe here")
	return nil
}

// Acquire and Release are the two halves of an exported lock.
func (j *Job) Acquire() {
	j.mu.Lock()
}

func (j *Job) Release() {
	j.mu.Unlock()
}
