package pool

import "sync"

type Task func()

type Pool struct {
	tasks   chan Task
	workers sync.WaitGroup
}

func (p *Pool) Start(n int) {
	for i := 0; i < n; i++ {
		go func() {
~>			p.workers.Add(1)
			defer p.workers.Done()
			for t := range p.tasks {
				t()
			}
		}()
	}
}

func (p *Pool) Stop() {
	close(p.tasks)
	p.workers.Wait()
}

func Spawn(done *sync.WaitGroup, jobs []Task) {
	for _, j := range jobs {
		j := j
		go func() {
			// register this worker
~>			done.Add(1)
			defer done.Done()
			j()
		}()
	}
}
