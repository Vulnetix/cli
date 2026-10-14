package warm

import "sync"

// Never write:
//
//	go func() {
//		wg.Add(1)
//		defer wg.Done()
//	}()
func Run(wg *sync.WaitGroup, f func()) {
	wg.Add(1)
	go func() {
		// wg.Add(1) belongs before the go statement, as above.
		defer wg.Done()
		f()
	}()
}
