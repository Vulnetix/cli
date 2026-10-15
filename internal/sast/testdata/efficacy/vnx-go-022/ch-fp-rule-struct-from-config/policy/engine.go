package policy

import (
	"os"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"gopkg.in/yaml.v3"
)

type Rule struct {
	Name string `yaml:"name"`
	When string `yaml:"when"`
}

func Load(path string) ([]*vm.Program, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	var out []*vm.Program
	for _, rule := range rules {
		p, err := compileRule(rule)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func compileRule(rule Rule) (*vm.Program, error) {
	return expr.Compile(rule.When, expr.AsBool())
}
