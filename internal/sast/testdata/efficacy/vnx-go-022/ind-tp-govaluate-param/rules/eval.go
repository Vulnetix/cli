package rules

import "github.com/Knetic/govaluate"

func Evaluate(userExpr string, params map[string]any) (any, error) {
~>	e, err := govaluate.NewEvaluableExpression(userExpr)
	if err != nil {
		return nil, err
	}
	return e.Evaluate(params)
}
