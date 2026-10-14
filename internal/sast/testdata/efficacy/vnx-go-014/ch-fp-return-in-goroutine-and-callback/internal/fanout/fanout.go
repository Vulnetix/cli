package fanout

import "sync"

type Hub struct {
	mu   sync.Mutex
	subs []func(string) bool
}

func (h *Hub) Publish(msg string) {
	h.mu.Lock()
	subs := append([]func(string) bool(nil), h.subs...)
	h.mu.Unlock()
	for _, s := range subs {
		go func(s func(string) bool) {
			if !s(msg) {
				return
			}
		}(s)
	}
}

func (h *Hub) Filter(keep func(string) bool) {
	h.mu.Lock()
	h.subs = filter(h.subs, func(f func(string) bool) bool {
		if f == nil {
			return false
		}
		return true
	})
	h.mu.Unlock()
}

func filter(in []func(string) bool, ok func(func(string) bool) bool) []func(string) bool {
	return in
}
