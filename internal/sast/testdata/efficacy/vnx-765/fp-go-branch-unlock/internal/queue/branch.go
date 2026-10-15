package queue

func (q *Queue) Take() (int, bool) {
	q.mu.Lock()
	if len(q.items) == 0 {
		q.mu.Unlock()
		return 0, false
	}
	v := q.items[0]
	q.mu.Unlock()
	return v, true
}

func (q *Queue) Switch(k int) {
	q.mu.Lock()
	switch k {
	case 1:
		q.mu.Unlock()
		one()
	default:
		q.mu.Unlock()
	}
}
