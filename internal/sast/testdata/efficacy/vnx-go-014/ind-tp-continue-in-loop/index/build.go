package index

import "sync"

var mu sync.Mutex
var byID = map[string]Doc{}

func Build(docs []Doc) {
	for _, d := range docs {
~>		mu.Lock()
		if d.ID == "" {
			continue
		}
		byID[d.ID] = d
		mu.Unlock()
	}
}
