package rules

import (
	"html/template"
	"os"

	"github.com/expr-lang/expr"
	"github.com/google/cel-go/cel"
)

type Rule struct {
	Name, When string
}

// Expression engines exist to evaluate configured rules. Rules the operator
// writes in a config file are not request data.
func Load(rules []Rule, env map[string]any) error {
	for _, r := range rules {
		if _, err := expr.Compile(r.When, expr.Env(env)); err != nil {
			return err
		}
	}
	celEnv, err := cel.NewEnv(cel.Variable("x", cel.IntType))
	if err != nil {
		return err
	}
	src, _ := os.ReadFile("policy.cel")
	_, iss := celEnv.Compile(string(src))
	return iss.Err()
}

// Templates parsed from the program's own files.
func Pages() (*template.Template, error) {
	body, err := os.ReadFile("templates/index.html")
	if err != nil {
		return nil, err
	}
	return template.New("index").Parse(string(body))
}
