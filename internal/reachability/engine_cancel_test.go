package reachability

import (
	"context"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/internal/treesitter"
)

// A parse halted by cancellation leaves the parser holding its half-built
// state, and tree-sitter resumes that parse on the next call. A pooled parser
// that kept it would hand the next file a tree with the previous file's byte
// offsets, and reading a capture panics with "slice bounds out of range".
func TestRunAfterCancelledParseDoesNotReuseHaltedState(t *testing.T) {
	e := NewEngine()
	big := []byte(strings.Repeat("def handler_function_name(argument):\n    return argument + 1\n", 20000))
	small := []byte("x = 1\n")
	const query = `((identifier) @id (#eq? @id "x"))`

	for i := 0; i < 50; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _ = e.Run(ctx, treesitter.LangPython, big, query)

		ms, err := e.Run(context.Background(), treesitter.LangPython, small, query)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if len(ms) != 1 || ms[0].Captures["id"] != "x" {
			t.Fatalf("run %d: want one capture of x, got %+v", i, ms)
		}
	}
}
