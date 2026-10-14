package build

import "sync"

type Step struct{ Run func() }

type Target struct{ Steps []Step }

func BuildAll(targets []Target) {
	var wg sync.WaitGroup
	wg.Add(len(targets))
	for _, t := range targets {
		go func(t Target) {
			defer wg.Done()
			for _, s := range t.Steps {
				wg.Add(1)
				go func(s Step) {
					defer wg.Done()
					s.Run()
				}(s)
			}
		}(t)
	}
	wg.Wait()
}
