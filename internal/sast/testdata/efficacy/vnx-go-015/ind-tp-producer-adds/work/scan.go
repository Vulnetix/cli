package work

import "sync"

func Scan(paths []string) {
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
