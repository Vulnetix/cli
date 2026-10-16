package rules

import "github.com/expr-lang/expr"

type Rule struct {
	Name string
	When string
}

func CompileAll(cfg []Rule, env map[string]any) error {
	for _, r := range cfg {
		if _, err := expr.Compile(r.When, expr.Env(env)); err != nil {
			return err
		}
	}
	return nil
}
