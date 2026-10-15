package worker

import (
	"log"
	"sync"
)

type queue struct {
	mu    sync.Mutex
	items []int
}

func (q *queue) Pop() (int, bool) {
	q.mu.Lock()
	if len(q.items) == 0 {
		q.mu.Unlock()
		return 0, false
	}
	v := q.items[0]
	q.items = q.items[1:]
	q.mu.Unlock()
	return v, true
}

func (q *queue) Explain() {
	// q.mu.Unlock() is called once per Lock.
	log.Println("q.mu.Unlock() twice is fatal")
}
