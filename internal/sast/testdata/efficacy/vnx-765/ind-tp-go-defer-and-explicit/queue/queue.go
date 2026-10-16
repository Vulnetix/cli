package queue

import "sync"

type Q struct {
	mu    sync.Mutex
	items []int
}

func (q *Q) Pop() (int, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
~>		q.mu.Unlock()
		return 0, false
	}
	v := q.items[0]
	q.items = q.items[1:]
	return v, true
}
