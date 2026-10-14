package index

import "sync"

type Doc struct {
	ID   string
	Body string
}

var (
	mu    sync.Mutex
	byID  = map[string]Doc{}
)

// Add skips empty documents, but the skip jumps back to the top of the loop
// with the lock still held, so the next iteration's Lock deadlocks.
func Add(docs []Doc) {
	for _, d := range docs {
~>		mu.Lock()
		if d.ID == "" {
			continue
		}
		byID[d.ID] = d
		mu.Unlock()
	}
}
