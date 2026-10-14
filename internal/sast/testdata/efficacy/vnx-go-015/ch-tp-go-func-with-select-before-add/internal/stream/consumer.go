package stream

import (
	"context"
	"sync"
)

type Consumer struct {
	wg sync.WaitGroup
}

func (c *Consumer) Consume(ctx context.Context, in <-chan []byte, handle func([]byte)) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-in:
~>				c.wg.Add(1)
				handle(msg)
				c.wg.Done()
			}
		}
	}()
}

func (c *Consumer) Drain() { c.wg.Wait() }
