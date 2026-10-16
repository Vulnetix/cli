package api

import (
	"net/http"

	"github.com/expr-lang/expr"
)

func Filter(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("filter")
~>	program, err := expr.Compile(q, expr.Env(map[string]any{"age": 0}))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	_ = program
}
