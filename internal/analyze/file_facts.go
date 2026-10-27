package analyze

// Per-file graph facts: what the file and symbol collectors read from one source file.
//
// Everything here is a pure function of the file's language and text: no ids, no import
// resolution, no caps. That is what lets the files be read in parallel and served from the
// graph cache, while everything that depends on other files or on order (record ids, symbol
// ids, the caps, import and call resolution) stays in the collectors' sequential merge, in
// the same order as before. One parse runs the decision, symbol and call queries together;
// the collectors used to parse each file three times.

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/vulnetix/cli/v3/internal/reachability"
	"github.com/vulnetix/cli/v3/internal/treesitter"
)

// queryOutcome is what happened to one query on one file.
type queryOutcome uint8

const (
	queryNone   queryOutcome = iota // the language has no such query
	queryRan                        // it ran; its matches are recorded
	queryFailed                     // it did not compile or the file did not parse
)

// symbolFact is one symbol-query match that the symbol collector keeps: an import
// (Import set) or a definition (Kind and Name set), in match order.
type symbolFact struct {
	Import    string `json:"i,omitempty"`
	Kind      string `json:"k,omitempty"`
	Name      string `json:"n,omitempty"`
	StartLine int    `json:"s,omitempty"`
	EndLine   int    `json:"e,omitempty"`
}

// callFact is one call-query match with a name.
type callFact struct {
	Line     int    `json:"l"`
	Name     string `json:"n"`
	Receiver string `json:"r,omitempty"`
}

type fileFacts struct {
	// Read is false when the file could not be read; nothing else is set then.
	Read       bool         `json:"read"`
	Lines      int          `json:"lines,omitempty"`
	Complexity *int         `json:"cx,omitempty"`
	Decision   queryOutcome `json:"dq"`
	Symbol     queryOutcome `json:"sq"`
	Call       queryOutcome `json:"cq"`
	Symbols    []symbolFact `json:"sym,omitempty"`
	Calls      []callFact   `json:"calls,omitempty"`
}

// computeFileFacts reads src as lang, running every query the language has on one parse.
func computeFileFacts(ctx context.Context, engine *reachability.Engine, lang treesitter.LanguageID, src []byte) *fileFacts {
	ff := &fileFacts{Read: true, Lines: strings.Count(string(src), "\n") + 1}

	var queries []string
	slot := func(q string, ok bool) int {
		if !ok {
			return -1
		}
		queries = append(queries, q)
		return len(queries) - 1
	}
	dq, okD := decisionQueries[lang]
	sq, okS := symbolQueries[lang]
	cq, okC := callQueries[lang]
	di, si, ci := slot(dq, okD), slot(sq, okS), slot(cq, okC)
	if len(queries) == 0 {
		return ff
	}
	matches, errs := engine.RunAll(ctx, lang, src, queries)

	if di >= 0 {
		if errs[di] != nil {
			ff.Decision = queryFailed
		} else {
			ff.Decision = queryRan
			// Cyclomatic complexity: decision points plus one.
			c := len(matches[di]) + 1
			ff.Complexity = &c
		}
	}
	if si >= 0 {
		if errs[si] != nil {
			ff.Symbol = queryFailed
		} else {
			ff.Symbol = queryRan
			for _, m := range matches[si] {
				if imp := m.Captures["import.source"]; imp != "" {
					ff.Symbols = append(ff.Symbols, symbolFact{Import: imp})
					continue
				}
				kind, name := symbolOf(m.Captures)
				if kind == "" || name == "" {
					continue
				}
				ff.Symbols = append(ff.Symbols, symbolFact{Kind: kind, Name: name, StartLine: m.StartLine, EndLine: m.EndLine})
			}
		}
	}
	if ci >= 0 {
		if errs[ci] != nil {
			ff.Call = queryFailed
		} else {
			ff.Call = queryRan
			for _, m := range matches[ci] {
				name := strings.TrimSpace(m.Captures["call.name"])
				if name == "" {
					continue
				}
				ff.Calls = append(ff.Calls, callFact{Line: m.StartLine, Name: name, Receiver: strings.TrimSpace(m.Captures["call.receiver"])})
			}
		}
	}
	return ff
}

// graphWorkers is how many files are read and parsed at once: Options.Workers when set, else
// VULNETIX_GRAPH_WORKERS, else the cores.
func graphWorkers(opts Options) int {
	if opts.Workers > 0 {
		return opts.Workers
	}
	if v := strings.TrimSpace(os.Getenv("VULNETIX_GRAPH_WORKERS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			return n
		}
	}
	return max(1, runtime.GOMAXPROCS(0))
}

// eachIndex runs fn(i) for every i in [0, n) on up to workers goroutines. Results go into
// slots the caller owns, so the merge that follows reads them in index order and the output
// does not depend on scheduling.
func eachIndex(n, workers int, fn func(i int)) {
	workers = max(1, min(workers, n))
	if workers == 1 {
		for i := range n {
			fn(i)
		}
		return
	}
	var next atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= n {
					return
				}
				fn(i)
			}
		}()
	}
	wg.Wait()
}
