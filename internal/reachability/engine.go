package reachability

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/vulnetix/cli/v3/internal/treesitter"
)

// Engine compiles and runs tree-sitter queries against source files. It
// is safe for concurrent use; parsers are not shared but are pooled per
// language.
type Engine struct {
	mu      sync.Mutex
	pools   map[treesitter.LanguageID]*parserPool
	queries map[string]*compiledQuery
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
	matches, errs := e.RunAll(ctx, id, source, []string{queryText})
	return matches[0], errs[0]
}

// RunAll runs every query in queryTexts against one parse of source, returning
// each query's matches and error in the same order.
//
// A scan runs a hundred-odd queries against each file. Running them one Run at
// a time parsed the file and compiled the query again for every one; the tree
// is the same for every query and a compiled query is the same for every file,
// so the file is parsed once here and each query is compiled once per engine.
// Each query still fails on its own: a bad pattern costs that query only.
func (e *Engine) RunAll(ctx context.Context, id treesitter.LanguageID, source []byte, queryTexts []string) ([][]QueryMatch, []error) {
	matches := make([][]QueryMatch, len(queryTexts))
	errs := make([]error, len(queryTexts))
	fail := func(err error) ([][]QueryMatch, []error) {
		for i := range errs {
			matches[i], errs[i] = nil, err
		}
		return matches, errs
	}
	pp := e.poolFor(id)
	if pp == nil {
		return fail(fmt.Errorf("unsupported language %q", id))
	}
	tree, release, err := e.parse(ctx, pp, source)
	if err != nil {
		return fail(err)
	}
	defer release()
	e.precompile(pp, queryTexts)
	for i, text := range queryTexts {
		matches[i], errs[i] = e.exec(pp, tree, source, text)
	}
	return matches, errs
}

// parse parses source with a pooled parser. release closes the tree and then
// returns the parser to the pool, in that order, as Run always did.
func (e *Engine) parse(ctx context.Context, pp *parserPool, source []byte) (tree *sitter.Tree, release func(), err error) {
	defer func() {
		if r := recover(); r != nil {
			tree, release, err = nil, nil, fmt.Errorf("parse failed: %v", r)
		}
	}()
	parser := pp.pool.Get().(*sitter.Parser)
	tree, err = parser.ParseCtx(ctx, nil, source)
	if err != nil {
		// A halted parse (cancellation or operation limit) leaves the parser
		// holding its half-built state, and tree-sitter resumes it on the
		// next call — against whatever source that call passes. Pooling it
		// would hand another file a tree with this file's byte offsets, which
		// panics in Node.Content. A cancellation racing a completed parse can
		// also leave go-tree-sitter's cancel flag set. Discard the parser.
		parser.Close()
		return nil, nil, fmt.Errorf("parse failed: %w", err)
	}

	// Belt and braces: never run predicates over a tree that does not
	// describe this source.
	if int(tree.RootNode().EndByte()) > len(source) {
		span := tree.RootNode().EndByte()
		tree.Close()
		pp.pool.Put(parser)
		return nil, nil, fmt.Errorf("parse failed: tree spans %d bytes, source has %d", span, len(source))
	}
	return tree, func() { tree.Close(); pp.pool.Put(parser) }, nil
}

// compiledQuery is a query compiled once per engine, or the error compiling it
// gave. A compiled query is read-only, so concurrent cursors may share it.
type compiledQuery struct {
	once sync.Once
	q    *sitter.Query
	err  error
}

// compile returns text compiled for pp's language, compiling it on first use.
// Compiles of different queries run at once: the engine's lock only covers the
// map, and each entry compiles once however many callers ask for it.
func (e *Engine) compile(pp *parserPool, text string) (*sitter.Query, error) {
	key := fmt.Sprintf("%p\x00%s", pp, text)
	e.mu.Lock()
	if e.queries == nil {
		e.queries = map[string]*compiledQuery{}
	}
	c, ok := e.queries[key]
	if !ok {
		c = &compiledQuery{}
		e.queries[key] = c
	}
	e.mu.Unlock()
	c.once.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				c.q, c.err = nil, fmt.Errorf("query compile failed: %v", r)
			}
		}()
		q, err := sitter.NewQuery([]byte(text), pp.lang)
		if err != nil {
			err = fmt.Errorf("query compile failed: %w", err)
		}
		c.q, c.err = q, err
	})
	return c.q, c.err
}

// precompile compiles queryTexts across the CPUs before they run. A query
// compile is CPU-bound and, for a large grammar such as Ruby's, costs tens of
// milliseconds, so a scan's hundred-odd queries compiled one after another
// held a single-file scan for seconds. Each query still compiles once.
func (e *Engine) precompile(pp *parserPool, queryTexts []string) {
	workers := min(runtime.GOMAXPROCS(0), len(queryTexts))
	if workers < 2 {
		return
	}
	next := make(chan string)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for text := range next {
				_, _ = e.compile(pp, text)
			}
		}()
	}
	for _, text := range queryTexts {
		next <- text
	}
	close(next)
	wg.Wait()
}

// exec runs one query over a parsed tree.
func (e *Engine) exec(pp *parserPool, tree *sitter.Tree, source []byte, text string) (out []QueryMatch, err error) {
	// go-tree-sitter compiles every #match? / #not-match? pattern with
	// regexp.MustCompile while filtering matches, so a query whose regex does not compile
	// panics instead of failing. Queries come from the server, and one bad pattern used to
	// crash the whole scan (exit status 2). It costs that query only.
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("query failed: %v", r)
		}
	}()
	q, err := e.compile(pp, text)
	if err != nil {
		return nil, err
	}

	qc := sitter.NewQueryCursor()
	defer qc.Close()
	qc.Exec(q, tree.RootNode())

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
