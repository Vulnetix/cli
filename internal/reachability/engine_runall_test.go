package reachability

import (
	"context"
	"reflect"
	"testing"

	"github.com/vulnetix/cli/v3/internal/treesitter"
)

func TestRunAllMatchesRunningEachQuery(t *testing.T) {
	src := []byte(`package main

import "net/http"

func main() {
	http.Get("https://example.com")
	println("hi")
}
`)
	queries := []string{
		`(call_expression function: (selector_expression operand: (identifier) @pkg field: (field_identifier) @fn)) @call`,
		`(call_expression function: (identifier) @fn (#eq? @fn "println")) @call`,
		`(this is not a valid query`,
		`(call_expression function: (identifier) @fn (#match? @fn "[")) @call`, // panics in go-tree-sitter
		`(import_spec path: (interpreted_string_literal) @path)`,
	}
	ctx := context.Background()
	all, errs := NewEngine().RunAll(ctx, treesitter.LangGo, src, queries)
	single := NewEngine()
	for i, q := range queries {
		want, wantErr := single.Run(ctx, treesitter.LangGo, src, q)
		if (errs[i] == nil) != (wantErr == nil) {
			t.Fatalf("query %d: RunAll error %v, Run error %v", i, errs[i], wantErr)
		}
		if !reflect.DeepEqual(all[i], want) {
			t.Fatalf("query %d: RunAll %+v, Run %+v", i, all[i], want)
		}
	}
	if len(all[0]) == 0 || len(all[1]) != 1 || errs[2] == nil || errs[3] == nil {
		t.Fatalf("fixture drifted: %v %v", all, errs)
	}
}
