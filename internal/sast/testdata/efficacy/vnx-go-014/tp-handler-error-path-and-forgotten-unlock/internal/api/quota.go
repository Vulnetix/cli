package api

import (
	"encoding/json"
	"net/http"
	"sync"
)

type Quotas struct {
	mu   sync.RWMutex
	used map[string]int
}

// Charge returns on a bad request body while holding the write lock; every
// later request blocks on q.mu.
func (q *Quotas) Charge(w http.ResponseWriter, r *http.Request) {
~>	q.mu.Lock()
	var req struct{ Tenant string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	q.used[req.Tenant]++
	q.mu.Unlock()
}

// Used is correct.
func (q *Quotas) Used(tenant string) int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.used[tenant]
}

// Reset forgets the Unlock entirely; Used's correct locking elsewhere does not
// release this one.
func (q *Quotas) Reset() {
~>	q.mu.Lock()
	q.used = map[string]int{}
}

// Snapshot locks and unlocks, so it is no release half for Reset.
func (q *Quotas) Snapshot() map[string]int {
	q.mu.Lock()
	out := make(map[string]int, len(q.used))
	for k, v := range q.used {
		out[k] = v
	}
	q.mu.Unlock()
	return out
}
