package engine

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
)

// Sigma rules over process starts.
//
// The sensor sees process starts (from Tetragon), so it evaluates Sigma rules
// whose logsource category is process_creation, with the fields a process
// start carries: Image, CommandLine, ParentImage, ParentCommandLine,
// CurrentDirectory, User. A rule for another logsource, or one using a field
// or modifier this evaluator does not have, is rejected with that reason
// rather than half-evaluated: a selection that silently ignores a field
// matches far more than its author meant.
//
// Supported: field lists (OR), field maps (AND), the modifiers contains,
// startswith, endswith, re, all and cased, keyword-free conditions with and,
// or, not, parentheses, "1 of <pattern>", "all of <pattern>" and "them".

// Process is the event a Sigma rule is evaluated against.
type Process struct {
	Image             string
	CommandLine       string
	ParentImage       string
	ParentCommandLine string
	CurrentDirectory  string
	User              string
}

func (p Process) field(name string) (string, bool) {
	switch name {
	case "Image":
		return p.Image, true
	case "CommandLine":
		return p.CommandLine, true
	case "ParentImage":
		return p.ParentImage, true
	case "ParentCommandLine":
		return p.ParentCommandLine, true
	case "CurrentDirectory":
		return p.CurrentDirectory, true
	case "User":
		return p.User, true
	}

	return "", false
}

type sigmaMatcher struct {
	field string
	all   bool
	tests []func(string) bool
}

type sigmaSelection []sigmaMatcher // AND of matchers

type sigmaRule struct {
	ref        decide.RuleRef
	title      string
	selections map[string][]sigmaSelection // name -> OR of selections
	cond       sigmaExpr
}

func compileSigma(body string) (*sigmaRule, string) {
	var doc struct {
		Title     string `yaml:"title"`
		LogSource struct {
			Category string `yaml:"category"`
			Product  string `yaml:"product"`
		} `yaml:"logsource"`
		Detection map[string]yaml.Node `yaml:"detection"`
	}
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		return nil, "not a Sigma rule: " + firstLine(err.Error())
	}
	if doc.LogSource.Category != "process_creation" {
		return nil, fmt.Sprintf("logsource %q: this sensor evaluates process_creation rules only", coalesceStr(doc.LogSource.Category, doc.LogSource.Product))
	}
	condNode, ok := doc.Detection["condition"]
	if !ok {
		return nil, "detection has no condition"
	}
	var condition string
	if err := condNode.Decode(&condition); err != nil {
		return nil, "condition must be one string"
	}

	r := &sigmaRule{title: doc.Title, selections: map[string][]sigmaSelection{}}
	for name, node := range doc.Detection {
		if name == "condition" || name == "timeframe" {
			continue
		}
		sels, reason := compileSelection(&node)
		if reason != "" {
			return nil, name + ": " + reason
		}
		r.selections[name] = sels
	}
	names := make([]string, 0, len(r.selections))
	for n := range r.selections {
		names = append(names, n)
	}
	expr, err := parseCondition(condition, names)
	if err != nil {
		return nil, "condition: " + err.Error()
	}
	r.cond = expr

	return r, ""
}

// compileSelection reads a selection: a map of field to value(s) (AND), or a
// list of such maps (OR). A bare keyword list is not supported: it means
// "anywhere in the event", which a process start does not have.
func compileSelection(node *yaml.Node) ([]sigmaSelection, string) {
	switch node.Kind {
	case yaml.MappingNode:
		s, reason := compileMap(node)
		if reason != "" {
			return nil, reason
		}

		return []sigmaSelection{s}, ""
	case yaml.SequenceNode:
		var out []sigmaSelection
		for _, item := range node.Content {
			if item.Kind != yaml.MappingNode {
				return nil, "keyword searches are not supported"
			}
			s, reason := compileMap(item)
			if reason != "" {
				return nil, reason
			}
			out = append(out, s)
		}

		return out, ""
	}

	return nil, "keyword searches are not supported"
}

func compileMap(node *yaml.Node) (sigmaSelection, string) {
	var sel sigmaSelection
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, val := node.Content[i].Value, node.Content[i+1]
		parts := strings.Split(key, "|")
		field := parts[0]
		if _, ok := (Process{}).field(field); !ok {
			return nil, "field " + field + " is not on a process start"
		}
		var values []string
		switch val.Kind {
		case yaml.ScalarNode:
			values = []string{val.Value}
		case yaml.SequenceNode:
			for _, v := range val.Content {
				values = append(values, v.Value)
			}
		default:
			return nil, "field " + field + " has a value that is not a string or list"
		}
		m := sigmaMatcher{field: field}
		mode, cased := "equals", false
		for _, mod := range parts[1:] {
			switch mod {
			case "contains", "startswith", "endswith", "re":
				mode = mod
			case "all":
				m.all = true
			case "cased":
				cased = true
			default:
				return nil, "modifier " + mod + " is not supported"
			}
		}
		for _, v := range values {
			test, reason := valueTest(mode, v, cased)
			if reason != "" {
				return nil, reason
			}
			m.tests = append(m.tests, test)
		}
		sel = append(sel, m)
	}

	return sel, ""
}

// valueTest builds one comparison. Sigma compares case-insensitively unless
// told otherwise, and a plain value may use * and ? wildcards.
func valueTest(mode, v string, cased bool) (func(string) bool, string) {
	norm := func(s string) string {
		if cased {
			return s
		}

		return strings.ToLower(s)
	}
	want := norm(v)
	switch mode {
	case "contains":
		return func(s string) bool { return strings.Contains(norm(s), want) }, ""
	case "startswith":
		return func(s string) bool { return strings.HasPrefix(norm(s), want) }, ""
	case "endswith":
		return func(s string) bool { return strings.HasSuffix(norm(s), want) }, ""
	case "re":
		re, err := regexp.Compile(v)
		if err != nil {
			return nil, "regex does not compile in RE2: " + err.Error()
		}

		return re.MatchString, ""
	}
	if strings.ContainsAny(want, "*?") {
		return func(s string) bool {
			ok, _ := path.Match(want, norm(s))

			return ok
		}, ""
	}

	return func(s string) bool { return norm(s) == want }, ""
}

func (m sigmaMatcher) match(p Process) bool {
	value, _ := p.field(m.field)
	if m.all {
		for _, t := range m.tests {
			if !t(value) {
				return false
			}
		}

		return true
	}
	for _, t := range m.tests {
		if t(value) {
			return true
		}
	}

	return false
}

func (r *sigmaRule) selectionMatches(name string, p Process) bool {
	for _, sel := range r.selections[name] {
		ok := true
		for _, m := range sel {
			if !m.match(p) {
				ok = false

				break
			}
		}
		if ok {
			return true
		}
	}

	return false
}

// MatchProcess evaluates the Sigma rules against one process start.
func (s *Set) MatchProcess(p Process) []Hit {
	var hits []Hit
	for _, r := range s.sigma {
		if r.cond.eval(r, p) {
			hits = append(hits, Hit{Rule: r.ref, Detail: r.title})
		}
	}

	return hits
}

// ── the condition language ──────────────────────────────────────────────────

type sigmaExpr interface {
	eval(r *sigmaRule, p Process) bool
}

type exprAnd struct{ a, b sigmaExpr }
type exprOr struct{ a, b sigmaExpr }
type exprNot struct{ a sigmaExpr }
type exprSel struct{ name string }
type exprQuant struct {
	all   bool
	names []string
}

func (e exprAnd) eval(r *sigmaRule, p Process) bool { return e.a.eval(r, p) && e.b.eval(r, p) }
func (e exprOr) eval(r *sigmaRule, p Process) bool  { return e.a.eval(r, p) || e.b.eval(r, p) }
func (e exprNot) eval(r *sigmaRule, p Process) bool { return !e.a.eval(r, p) }
func (e exprSel) eval(r *sigmaRule, p Process) bool { return r.selectionMatches(e.name, p) }
func (e exprQuant) eval(r *sigmaRule, p Process) bool {
	for _, n := range e.names {
		m := r.selectionMatches(n, p)
		if e.all && !m {
			return false
		}
		if !e.all && m {
			return true
		}
	}

	return e.all
}

type condParser struct {
	toks  []string
	pos   int
	names []string
}

func parseCondition(cond string, names []string) (sigmaExpr, error) {
	if strings.Contains(cond, "|") {
		return nil, fmt.Errorf("aggregations (|) are not supported")
	}
	cond = strings.NewReplacer("(", " ( ", ")", " ) ").Replace(cond)
	p := &condParser{toks: strings.Fields(cond), names: names}
	e, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("unexpected %q", p.toks[p.pos])
	}

	return e, nil
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}

	return ""
}

func (p *condParser) next() string { t := p.peek(); p.pos++; return t }

func (p *condParser) or() (sigmaExpr, error) {
	left, err := p.and()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "or") {
		p.next()
		right, err := p.and()
		if err != nil {
			return nil, err
		}
		left = exprOr{left, right}
	}

	return left, nil
}

func (p *condParser) and() (sigmaExpr, error) {
	left, err := p.unary()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "and") {
		p.next()
		right, err := p.unary()
		if err != nil {
			return nil, err
		}
		left = exprAnd{left, right}
	}

	return left, nil
}

func (p *condParser) unary() (sigmaExpr, error) {
	tok := p.next()
	switch {
	case tok == "":
		return nil, fmt.Errorf("ends early")
	case strings.EqualFold(tok, "not"):
		e, err := p.unary()
		if err != nil {
			return nil, err
		}

		return exprNot{e}, nil
	case tok == "(":
		e, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.next() != ")" {
			return nil, fmt.Errorf("unclosed parenthesis")
		}

		return e, nil
	case tok == "1" || strings.EqualFold(tok, "all") || strings.EqualFold(tok, "any"):
		if !strings.EqualFold(p.next(), "of") {
			return nil, fmt.Errorf("expected 'of' after %q", tok)
		}
		target := p.next()
		var names []string
		for _, n := range p.names {
			if target == "them" || n == target || (strings.HasSuffix(target, "*") && strings.HasPrefix(n, strings.TrimSuffix(target, "*"))) {
				names = append(names, n)
			}
		}
		if len(names) == 0 {
			return nil, fmt.Errorf("%q names no selection", target)
		}

		return exprQuant{all: strings.EqualFold(tok, "all"), names: names}, nil
	}
	for _, n := range p.names {
		if n == tok {
			return exprSel{tok}, nil
		}
	}

	return nil, fmt.Errorf("%q is not a selection", tok)
}

func coalesceStr(a, b string) string {
	if a != "" {
		return a
	}

	return b
}
