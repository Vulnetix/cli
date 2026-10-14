package warm

import "sync"

// The parent adds before each go statement; the Add calls after a closed
// goroutine belong to the next one.
func Warm(load func(string) error) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		load("users")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		load("orgs")
	}()

	wg.Add(2)
	go func() { defer wg.Done(); load("a") }()
	go func() { defer wg.Done(); load("b") }()
	wg.Wait()
}
