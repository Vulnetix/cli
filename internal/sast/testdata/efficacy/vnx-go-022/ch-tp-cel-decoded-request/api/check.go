package api

import (
	"encoding/json"
	"net/http"

	"github.com/google/cel-go/cel"
)

type checkRequest struct {
	Expression string `json:"expression"`
}

func Check(w http.ResponseWriter, r *http.Request) {
	var req checkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return
	}
	env, _ := cel.NewEnv(cel.Variable("user", cel.StringType))
~>	ast, iss := env.Compile(req.Expression)
	if iss.Err() != nil {
		return
	}
	prg, _ := env.Program(ast)
	prg.Eval(map[string]any{"user": "x"})
}
