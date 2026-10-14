package crawl

import "sync"

// The parent counts the producer before starting it, so the producer's own
// Add calls happen while the counter is above zero: Wait cannot return early.
func Crawl(seeds []string, visit func(string)) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, s := range seeds {
			wg.Add(1)
			go func(s string) {
				defer wg.Done()
				visit(s)
			}(s)
		}
	}()
	wg.Wait()
}
