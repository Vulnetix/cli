package queue

func (q *Queue) Wait() {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 {
		q.mu.Unlock()
		sleep()
		q.mu.Lock()
	}
}

func (q *Queue) Async() {
	q.mu.Lock()
	defer q.mu.Unlock()
	go func() {
		q.other.Lock()
		q.other.Unlock()
	}()
}

func (q *Queue) Plain() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}
