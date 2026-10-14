package sync2

import (
	"context"
	"sync"

	"golang.org/x/sync/errgroup"
)

type Node struct{ Children []*Node }

func Walk(ctx context.Context, roots []*Node, visit func(*Node) error) error {
	g, ctx := errgroup.WithContext(ctx)
	for _, r := range roots {
		r := r
		g.Go(func() error { return visit(r) })
	}
	return g.Wait()
}

func Visit(n *Node, wg *sync.WaitGroup, visit func(*Node)) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		visit(n)
		for _, c := range n.Children {
			wg.Add(1)
			go func(c *Node) {
				defer wg.Done()
				visit(c)
			}(c)
		}
	}()
}
