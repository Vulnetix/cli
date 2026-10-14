package web

import (
	"net/http"
	"regexp"
	"strings"
)

type Index interface {
	Eval(q string) []string
	Run(q string) error
}

// Go has no eval(); methods that happen to be called Eval or Run on the
// program's own types are not an interpreter.
func Search(w http.ResponseWriter, r *http.Request, idx Index) {
	q := r.URL.Query().Get("q")
	idx.Eval(q)
	idx.Run(q)
	re, err := regexp.Compile(regexp.QuoteMeta(q))
	if err == nil {
		_ = re
	}
	doc := "function f() { return eval(" + q + "); }"
	_ = strings.TrimSpace(doc)
	retrieval(q)
}

func retrieval(string) {}
