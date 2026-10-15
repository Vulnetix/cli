package queue

import "sync"

type Queue struct {
	mu    sync.Mutex
	items []int
}

func (q *Queue) Pop() (int, bool) {
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

func (q *Queue) Flush(send func([]int)) {
	q.mu.Lock()
	defer q.mu.Unlock()
	batch := q.items
	q.items = nil
~>	q.mu.Unlock()
	send(batch)
}
