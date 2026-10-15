package queue

func (q *Queue) Len() int {
	q.mu.RLock()
	n := len(q.items)
	q.mu.RUnlock()
	report(n)
~>	q.mu.RUnlock()
	return n
}
