package cache

import "sync"

// flushAsync runs in the background; its own WaitGroup is declared, added to
// and waited on inside the same goroutine.
func flushAsync(entries map[string][]byte, put func(string, []byte)) {
	go func() {
		var wg sync.WaitGroup
		for k, v := range entries {
			wg.Add(1)
			go func(k string, v []byte) {
				defer wg.Done()
				put(k, v)
			}(k, v)
		}
		wg.Wait()
	}()

	go func() {
		inner := new(sync.WaitGroup)
		inner.Add(1)
		go func() { defer inner.Done() }()
		inner.Wait()
	}()
}
