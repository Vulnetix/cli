package queue

import "sync"

type Q struct {
	mu    sync.Mutex
	cond  *sync.Cond
	items []int
}

func (q *Q) Pop() (int, bool) {
	q.mu.Lock()
	if len(q.items) == 0 {
		q.mu.Unlock()
		return 0, false
	}
	v := q.items[0]
	q.mu.Unlock()
	return v, true
}

func (q *Q) Wait() {
	q.mu.Lock()
	q.mu.Unlock()
	q.cond.Wait()
	q.mu.Lock()
	q.mu.Unlock()
}

func (q *Q) Pick(k int) {
	switch k {
	case 1:
		q.mu.Lock()
		q.mu.Unlock()
	case 2:
		q.mu.Lock()
		q.mu.Unlock()
	}
}

func (q *Q) Go() {
	q.mu.Lock()
	defer q.mu.Unlock()
	go func() {
		q.mu.Lock()
		q.mu.Unlock()
	}()
}
