package versions

import (
	"fmt"
	"strings"
)

// Op is a comparison operator in a version constraint.
type Op string

const (
	OpEq       Op = "="
	OpLt       Op = "<"
	OpLte      Op = "<="
	OpGt       Op = ">"
	OpGte      Op = ">="
	OpNeq      Op = "!="
	OpWildcard Op = "*"
)

// Constraint is a single operator + version comparison.
type Constraint struct {
	Op      Op
	Version Version
}

// Range is a set of constraints ANDed together.
type Range struct {
	Constraints []Constraint
}

// RangeSet is a set of ranges ORed together.
type RangeSet struct {
	Ranges   []Range
	Original string
}

// IsWildcardRange reports whether a range expression means "all versions".
// Mirrors (and supersedes) the historical CLI heuristics.
func IsWildcardRange(s string) bool {
	switch normalizeRangeString(s) {
	case "*", "x", "X", ">= 0", ">=0", ">= 0.0.0", ">=0.0.0", "<= 99999", "<=99999":
		return true
	}
	return false
}

// ParseRange parses a version range expression into a RangeSet.
//
// Grammar (canonical, as emitted by the VDB API):
//
//	RangeSet   := Range ( " || " Range )*          OR
//	Range      := Constraint ( " " Constraint )*   AND
//	Constraint := Op " "? Version | Version        bare Version ⇒ "="
//	Op         := "=" | "==" | "<" | "<=" | ">" | ">=" | "!="
//
// Additionally tolerated (never emitted): unicode operators (≥ ≤ ≠),
// v/V/npm: version prefixes, interval notation "[a, b)" / "(a, b]", and
// comma lists with disambiguation — items carrying operators make commas
// AND separators (">= 2.0.0, < 2.3.1"); all-bare items make commas an OR
// exact list ("1.14.1, 0.30.4" ⇒ "= 1.14.1 || = 0.30.4"). "*" matches all
// versions.
func ParseRange(s string) (RangeSet, error) {
	rs := RangeSet{Original: s}
	expr := normalizeRangeString(s)
	if expr == "" {
		return rs, fmt.Errorf("empty range")
	}
	if IsWildcardRange(expr) {
		rs.Ranges = []Range{{Constraints: []Constraint{{Op: OpWildcard, Version: Version{Wildcard: true, Original: expr}}}}}
		return rs, nil
	}

	// Interval notation: [a, b) / (a, b] / [a,) / (,b].
	if len(expr) >= 2 &&
		(expr[0] == '[' || expr[0] == '(') &&
		(expr[len(expr)-1] == ']' || expr[len(expr)-1] == ')') {
		r, err := parseInterval(expr)
		if err != nil {
			return rs, err
		}
		rs.Ranges = []Range{r}
		return rs, nil
	}

	for group := range strings.SplitSeq(expr, "||") {
		group = strings.TrimSpace(group)
		if group == "" {
			continue
		}
		groups, err := splitCommaGroup(group)
		if err != nil {
			return rs, err
		}
		for _, g := range groups {
			r, err := parseAndGroup(g)
			if err != nil {
				return rs, err
			}
			rs.Ranges = append(rs.Ranges, r)
		}
	}
	if len(rs.Ranges) == 0 {
		return rs, fmt.Errorf("no parseable constraints in %q", s)
	}
	return rs, nil
}

// splitCommaGroup applies the comma-disambiguation rule and returns one or
// more AND-group strings: items with operators join into a single AND group;
// all-bare items become independent exact-match groups (OR semantics).
func splitCommaGroup(group string) ([]string, error) {
	if !strings.Contains(group, ",") {
		return []string{group}, nil
	}
	items := strings.Split(group, ",")
	hasOp := false
	cleaned := make([]string, 0, len(items))
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		if strings.HasPrefix(it, "<") || strings.HasPrefix(it, ">") ||
			strings.HasPrefix(it, "=") || strings.HasPrefix(it, "!") {
			hasOp = true
		}
		cleaned = append(cleaned, it)
	}
	if len(cleaned) == 0 {
		return nil, fmt.Errorf("empty comma group %q", group)
	}
	if hasOp {
		// ">= 2.0.0, < 2.3.1" — commas are AND separators.
		return []string{strings.Join(cleaned, " ")}, nil
	}
	// "1.14.1, 0.30.4" — bare exact list, OR semantics.
	return cleaned, nil
}

// parseAndGroup parses space-separated constraints ANDed together.
// Operators may be attached (">=1.0.0") or detached (">= 1.0.0").
func parseAndGroup(group string) (Range, error) {
	var r Range
	tokens := strings.Fields(group)
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		op, rest := splitOp(tok)
		if op != "" && rest == "" {
			// Detached operator — consume the next token as its version.
			if i+1 >= len(tokens) {
				return r, fmt.Errorf("dangling operator %q in %q", op, group)
			}
			i++
			rest = tokens[i]
		}
		if op == "" {
			op = OpEq
		}
		if rest == "*" || rest == "x" || rest == "X" {
			r.Constraints = append(r.Constraints, Constraint{Op: OpWildcard, Version: Version{Wildcard: true, Original: rest}})
			continue
		}
		v, err := Parse(rest)
		if err != nil {
			return r, fmt.Errorf("unparseable version %q in range %q: %w", rest, group, err)
		}
		r.Constraints = append(r.Constraints, Constraint{Op: op, Version: v})
	}
	if len(r.Constraints) == 0 {
		return r, fmt.Errorf("no constraints in %q", group)
	}
	return r, nil
}

// splitOp splits a leading operator from a token. "==" normalizes to "=".
func splitOp(tok string) (Op, string) {
	for _, p := range []string{">=", "<=", "!=", "==", ">", "<", "="} {
		if strings.HasPrefix(tok, p) {
			op := Op(p)
			if op == "==" {
				op = OpEq
			}
			return op, strings.TrimSpace(tok[len(p):])
		}
	}
	if tok == "*" {
		return OpWildcard, ""
	}
	return "", tok
}

// parseInterval parses "[a, b)" style interval notation into an AND Range.
func parseInterval(expr string) (Range, error) {
	var r Range
	lowerInclusive := expr[0] == '['
	upperInclusive := expr[len(expr)-1] == ']'
	inner := expr[1 : len(expr)-1]
	parts := strings.SplitN(inner, ",", 2)
	if len(parts) != 2 {
		return r, fmt.Errorf("invalid interval %q", expr)
	}
	lowerStr := strings.TrimSpace(parts[0])
	upperStr := strings.TrimSpace(parts[1])
	if lowerStr != "" && lowerStr != "*" {
		v, err := Parse(lowerStr)
		if err != nil {
			return r, fmt.Errorf("invalid interval lower bound in %q: %w", expr, err)
		}
		op := OpGt
		if lowerInclusive {
			op = OpGte
		}
		r.Constraints = append(r.Constraints, Constraint{Op: op, Version: v})
	}
	if upperStr != "" && upperStr != "*" {
		v, err := Parse(upperStr)
		if err != nil {
			return r, fmt.Errorf("invalid interval upper bound in %q: %w", expr, err)
		}
		op := OpLt
		if upperInclusive {
			op = OpLte
		}
		r.Constraints = append(r.Constraints, Constraint{Op: op, Version: v})
	}
	if len(r.Constraints) == 0 {
		return r, fmt.Errorf("empty interval %q", expr)
	}
	return r, nil
}

// Contains reports whether v satisfies the range set (any OR group whose
// constraints all hold). Exact-match constraints honor the pseudo policy;
// relational constraints always use true SemVer ordering.
func (rs RangeSet) Contains(v Version, p PseudoPolicy) bool {
	for _, r := range rs.Ranges {
		if r.contains(v, p) {
			return true
		}
	}
	return false
}

func (r Range) contains(v Version, p PseudoPolicy) bool {
	for _, c := range r.Constraints {
		if !c.satisfies(v, p) {
			return false
		}
	}
	return len(r.Constraints) > 0
}

func (c Constraint) satisfies(v Version, p PseudoPolicy) bool {
	switch c.Op {
	case OpWildcard:
		return true
	case OpEq:
		return EqualExact(v, c.Version, p)
	case OpNeq:
		return !EqualExact(v, c.Version, p)
	case OpLt:
		return Compare(v, c.Version) < 0
	case OpLte:
		return Compare(v, c.Version) <= 0
	case OpGt:
		return Compare(v, c.Version) > 0
	case OpGte:
		// ">= 0" means "from the beginning" in vulnerability ranges: it
		// must include prereleases of 0.0.0 (e.g. Go pseudo-versions),
		// which SemVer otherwise orders before 0.0.0.
		return isZeroVersion(c.Version) || Compare(v, c.Version) >= 0
	}
	return false
}
