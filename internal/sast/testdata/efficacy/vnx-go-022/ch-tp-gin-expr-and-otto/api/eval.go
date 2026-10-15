package api

import (
	"net/http"

	"github.com/expr-lang/expr"
	"github.com/gin-gonic/gin"
	"github.com/robertkrimen/otto"
)

func Filter(c *gin.Context) {
~>	program, err := expr.Compile(c.Query("rule"), expr.AsBool())
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	expr.Run(program, map[string]any{})
}

func Script(w http.ResponseWriter, r *http.Request) {
	vm := otto.New()
	src := r.PostFormValue("js")
~>	value, err := vm.Run(
		src,
	)
	_ = value
	_ = err
}
