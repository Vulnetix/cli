package scan

import "sync"

// The producer goroutine is not counted, so Wait can see zero before it has
// added the first worker.
func Scan(paths []string, check func(string)) {
	var wg sync.WaitGroup
	go func() {
		for _, p := range paths {
~>			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				check(p)
			}(p)
		}
	}()
	wg.Wait()
}
