package rules

import (
	"net/http"

	"github.com/Knetic/govaluate"
	"github.com/expr-lang/expr"
	"github.com/gin-gonic/gin"
)

// Expression engines are sandboxed, but an expression the requester writes is
// still code the server runs: it can read every variable in the environment
// and loop until the request times out.
func Filter(w http.ResponseWriter, r *http.Request, env map[string]any) {
	q := r.URL.Query().Get("filter")
~>	program, err := expr.Compile(q, expr.Env(env))
	if err != nil {
		return
	}
	expr.Run(program, env)
}

func Price(c *gin.Context) {
	formula := c.Query("formula")
~>	e, err := govaluate.NewEvaluableExpression(formula)
	if err != nil {
		return
	}
	e.Evaluate(nil)
}
