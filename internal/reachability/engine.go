package reachability

import (
	"context"
	"fmt"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/vulnetix/cli/v2/internal/treesitter"
)

// Engine compiles and runs tree-sitter queries against source files. It
// is safe for concurrent use; parsers are not shared but are pooled per
// language.
type Engine struct {
	mu    sync.Mutex
	pools map[treesitter.LanguageID]*parserPool
}

// NewEngine returns a fresh engine.
func NewEngine() *Engine {
	return &Engine{pools: make(map[treesitter.LanguageID]*parserPool)}
}

type parserPool struct {
	lang *sitter.Language
	pool sync.Pool
}

func (e *Engine) poolFor(id treesitter.LanguageID) *parserPool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if pp, ok := e.pools[id]; ok {
		return pp
	}
	lang := treesitter.Grammar(id)
	if lang == nil {
		return nil
	}
	pp := &parserPool{lang: lang}
	pp.pool.New = func() any {
		p := sitter.NewParser()
		p.SetLanguage(lang)
		return p
	}
	e.pools[id] = pp
	return pp
}

// QueryMatch is a single match emitted by Engine.Run before being
// promoted to a reachability.Match (which adds file context).
type QueryMatch struct {
	StartLine int
	EndLine   int
	Captures  map[string]string
}

// Run parses source as the given language and executes queryText against
// it, returning every top-level match.
func (e *Engine) Run(ctx context.Context, id treesitter.LanguageID, source []byte, queryText string) ([]QueryMatch, error) {
	pp := e.poolFor(id)
	if pp == nil {
		return nil, fmt.Errorf("unsupported language %q", id)
	}
	parser := pp.pool.Get().(*sitter.Parser)
	defer pp.pool.Put(parser)

	tree, err := parser.ParseCtx(ctx, nil, source)
	if err != nil {
		return nil, fmt.Errorf("parse failed: %w", err)
	}
	defer tree.Close()

	q, err := sitter.NewQuery([]byte(queryText), pp.lang)
	if err != nil {
		return nil, fmt.Errorf("query compile failed: %w", err)
	}
	defer q.Close()

	qc := sitter.NewQueryCursor()
	defer qc.Close()
	qc.Exec(q, tree.RootNode())

	var out []QueryMatch
	for {
		m, ok := qc.NextMatch()
		if !ok {
			break
		}
		m = qc.FilterPredicates(m, source)
		if len(m.Captures) == 0 {
			continue
		}
		startRow := int(^uint(0) >> 1)
		endRow := 0
		caps := make(map[string]string, len(m.Captures))
		for _, c := range m.Captures {
			sp := c.Node.StartPoint()
			ep := c.Node.EndPoint()
			if int(sp.Row) < startRow {
				startRow = int(sp.Row)
			}
			if int(ep.Row) > endRow {
				endRow = int(ep.Row)
			}
			caps[q.CaptureNameForId(c.Index)] = c.Node.Content(source)
		}
		out = append(out, QueryMatch{
			StartLine: startRow + 1,
			EndLine:   endRow + 1,
			Captures:  caps,
		})
	}
	return out, nil
}
