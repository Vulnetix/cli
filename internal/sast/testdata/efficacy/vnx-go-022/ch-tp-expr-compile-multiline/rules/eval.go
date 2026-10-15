package rules

import (
	"net/http"

	"github.com/expr-lang/expr"
	"github.com/gin-gonic/gin"
)

func Evaluate(c *gin.Context) {
	rule := c.Query("rule")
	env := map[string]any{"user": c.GetString("user")}
~>	program, err := expr.Compile(
		rule,
		expr.Env(env),
	)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	out, _ := expr.Run(program, env)
	c.JSON(http.StatusOK, out)
}
