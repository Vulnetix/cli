package warm

import (
	"log"
	"sync"
)

// Warm can return before any cache is warmed: Wait may run before either
// goroutine has executed its Add.
func Warm(load func(string) error) {
	var wg sync.WaitGroup
	go func() {
~>		wg.Add(1)
		defer wg.Done()
		if err := load("users"); err != nil {
			log.Println(err)
		}
	}()
	go func() {
		defer wg.Done()
~>		wg.Add( 1 )
		load("orgs")
	}()
	wg.Wait()
}
