package engine

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	binregexp "rsc.io/binaryregexp"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
)

// YARA rules over files, in pure Go.
//
// The full YARA engine is C, and linking it would end the sensor's static,
// CGO-free build. This evaluates the subset most published detection rules
// use, and rejects a rule that needs anything else, by name, rather than
// matching it differently:
//
//   - strings: text ("..." with nocase, wide, ascii, fullword), hex
//     ({ 4D 5A ?? [2-4] 90 } with ?? wildcards, jumps and (a|b) alternation)
//     and regular expressions (/.../ with i and s, RE2 syntax)
//   - conditions: and, or, not, parentheses, $id, any of them, all of them,
//     N of them, any/all/N of ($prefix*), filesize compared with a number
//     (KB and MB suffixes), and uint8/16/32(offset) and their be forms
//     compared with a number
//
// Not supported, and rejected: imports and modules (pe, elf, math, hash),
// for loops, #count, @offset, !length, "at" and "in", private and global rule
// modifiers, rule references, xor, base64.

// MaxYaraFile bounds a file the sensor evaluates YARA rules against.
const MaxYaraFile = 64 << 20

type yaraString struct {
	id string
	re *binregexp.Regexp
}

type yaraRule struct {
	ref     decide.RuleRef
	name    string
	strings []yaraString
	cond    yaraExpr
}

var (
	yaraRuleHead    = regexp.MustCompile(`(?s)^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^{]*)?\{(.*)\}\s*$`)
	yaraRuleStart   = regexp.MustCompile(`(?m)^\s*rule\s`)
	yaraSection     = regexp.MustCompile(`(?:^|\s|\{)(meta|strings|condition)\s*:`)
	yaraStringStart = regexp.MustCompile(`(?:^|\s)\$[A-Za-z0-9_]*\s*=`)
	yaraUnsupported = []struct {
		re   *regexp.Regexp
		what string
	}{
		{regexp.MustCompile(`(?m)^\s*import\s+"`), "modules (import)"},
		{regexp.MustCompile(`\b(private|global)\s+rule\b`), "private or global rules"},
		{regexp.MustCompile(`\bfor\s+(any|all|\d+)\b`), "for loops"},
		{regexp.MustCompile(`#[A-Za-z_]\w*`), "string counts (#)"},
		{regexp.MustCompile(`@[A-Za-z_]\w*`), "string offsets (@)"},
		{regexp.MustCompile(`![A-Za-z_]\w*`), "string lengths (!)"},
		{regexp.MustCompile(`\$\w*\s+(at|in)\b`), "at and in"},
		{regexp.MustCompile(`\b(xor|base64|base64wide)\b`), "xor and base64 strings"},
		{regexp.MustCompile(`\b(pe|elf|math|hash|dotnet|cuckoo|magic)\.`), "module functions"},
	}
)

// compileYara compiles one rule. A feed entry with several rules is rejected:
// its matches could not be told apart.
func compileYara(body string) (*yaraRule, string) {
	src := stripYaraComments(body)
	for _, u := range yaraUnsupported {
		if u.re.MatchString(src) {
			return nil, u.what + " are not supported by this sensor"
		}
	}
	if len(yaraRuleStart.FindAllStringIndex(src, -1)) > 1 {
		return nil, "one feed entry holds several rules"
	}
	m := yaraRuleHead.FindStringSubmatch(src)
	if m == nil {
		return nil, "not a YARA rule"
	}
	r := &yaraRule{name: m[1]}
	sections := splitYaraSections(m[2])
	cond, ok := sections["condition"]
	if !ok {
		return nil, "the rule has no condition"
	}
	for _, line := range yaraStatements(sections["strings"]) {
		s, reason := compileYaraString(line)
		if reason != "" {
			return nil, reason
		}
		r.strings = append(r.strings, s)
	}
	expr, err := parseYaraCondition(cond, r.strings)
	if err != nil {
		return nil, "condition: " + err.Error()
	}
	r.cond = expr

	return r, ""
}

func stripYaraComments(s string) string {
	// Walk the text so a "//" inside a quoted string (stratum+tcp://, a URL)
	// stays part of the string.
	var b strings.Builder
	inString := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inString:
			b.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			} else if c == '"' {
				inString = false
			}
		case c == '"':
			inString = true
			b.WriteByte(c)
		case c == '/' && i+1 < len(s) && s[i+1] == '/':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			if i < len(s) {
				b.WriteByte('\n')
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return b.String()
			}
			i += end + 3
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}

	return b.String()
}

func splitYaraSections(body string) map[string]string {
	out := map[string]string{}
	locs := yaraSection.FindAllStringSubmatchIndex(body, -1)
	for i, loc := range locs {
		name := body[loc[2]:loc[3]]
		end := len(body)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		out[name] = strings.TrimSpace(body[loc[1]:end])
	}

	return out
}

// yaraStatements splits a strings section into one definition per $id, on one
// line or many.
func yaraStatements(section string) []string {
	locs := yaraStringStart.FindAllStringIndex(section, -1)
	var out []string
	for i, loc := range locs {
		end := len(section)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		if part := strings.TrimSpace(section[loc[0]:end]); part != "" {
			out = append(out, part)
		}
	}

	return out
}

var yaraDef = regexp.MustCompile(`(?s)^\$([A-Za-z0-9_]*)\s*=\s*(.+)$`)

func compileYaraString(def string) (yaraString, string) {
	m := yaraDef.FindStringSubmatch(strings.TrimSpace(def))
	if m == nil {
		return yaraString{}, "cannot read string definition " + firstLine(def)
	}
	id, value := "$"+m[1], strings.TrimSpace(m[2])
	var pattern string
	switch {
	case strings.HasPrefix(value, `"`):
		end := closingQuote(value)
		if end < 0 {
			return yaraString{}, id + ": unterminated text string"
		}
		text, err := strconv.Unquote(value[:end+1])
		if err != nil {
			return yaraString{}, id + ": cannot read text string: " + err.Error()
		}
		mods := strings.Fields(value[end+1:])
		nocase, wide, ascii, fullword := false, false, false, false
		for _, mod := range mods {
			switch mod {
			case "nocase":
				nocase = true
			case "wide":
				wide = true
			case "ascii":
				ascii = true
			case "fullword":
				fullword = true
			default:
				return yaraString{}, id + ": modifier " + mod + " is not supported"
			}
		}
		var alts []string
		if !wide || ascii {
			alts = append(alts, regexp.QuoteMeta(text))
		}
		if wide {
			var b strings.Builder
			for _, r := range text {
				b.WriteString(regexp.QuoteMeta(string(r)) + `\x00`)
			}
			alts = append(alts, b.String())
		}
		pattern = "(?:" + strings.Join(alts, "|") + ")"
		if fullword {
			pattern = `(?:^|[^A-Za-z0-9])` + pattern + `(?:[^A-Za-z0-9]|$)`
		}
		if nocase {
			pattern = "(?i)" + pattern
		}
	case strings.HasPrefix(value, "{"):
		end := strings.LastIndex(value, "}")
		if end < 0 {
			return yaraString{}, id + ": unterminated hex string"
		}
		p, reason := hexPattern(value[1:end])
		if reason != "" {
			return yaraString{}, id + ": " + reason
		}
		pattern = p
	case strings.HasPrefix(value, "/"):
		end := strings.LastIndex(value, "/")
		if end <= 0 {
			return yaraString{}, id + ": unterminated regular expression"
		}
		flags := ""
		for _, f := range strings.Fields(value[end+1:]) {
			switch f {
			case "i", "nocase":
				flags += "i"
			case "s":
				flags += "s"
			default:
				if strings.Trim(f, "is") != "" {
					return yaraString{}, id + ": regex modifier " + f + " is not supported"
				}
				flags += f
			}
		}
		pattern = value[1:end]
		if flags != "" {
			pattern = "(?" + flags + ")" + pattern
		}
	default:
		return yaraString{}, id + ": not a text, hex or regex string"
	}
	re, err := binregexp.Compile(pattern)
	if err != nil {
		return yaraString{}, id + ": does not compile in RE2: " + firstLine(err.Error())
	}

	return yaraString{id: id, re: re}, ""
}

func closingQuote(s string) int {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i
		}
	}

	return -1
}

// hexPattern turns a YARA hex string into a byte-level regular expression.
func hexPattern(hex string) (string, string) {
	toks := strings.FieldsFunc(hex, unicode.IsSpace)
	var b strings.Builder
	b.WriteString("(?s)")
	joined := strings.Join(toks, "")
	for i := 0; i < len(joined); {
		c := joined[i]
		switch {
		case c == '[':
			end := strings.IndexByte(joined[i:], ']')
			if end < 0 {
				return "", "unterminated jump"
			}
			lo, hi, ok := strings.Cut(joined[i+1:i+end], "-")
			switch {
			case !ok:
				b.WriteString(".{" + lo + "}")
			case hi == "":
				b.WriteString(".{" + lo + ",}")
			default:
				b.WriteString(".{" + lo + "," + hi + "}")
			}
			i += end + 1
		case c == '(' || c == ')' || c == '|':
			b.WriteByte(c)
			i++
		case i+1 < len(joined):
			pair := joined[i : i+2]
			switch {
			case pair == "??":
				b.WriteString(".")
			case pair[0] == '?' || pair[1] == '?':
				return "", "nibble wildcards are not supported"
			default:
				v, err := strconv.ParseUint(pair, 16, 8)
				if err != nil {
					return "", "bad hex byte " + pair
				}
				b.WriteString(fmt.Sprintf(`\x%02x`, v))
			}
			i += 2
		default:
			return "", "odd number of hex digits"
		}
	}

	return b.String(), ""
}

// MatchFile evaluates the YARA rules against a file's bytes.
func (s *Set) MatchFile(data []byte) []Hit {
	var hits []Hit
	for _, r := range s.yara {
		matched := map[string]bool{}
		for _, ys := range r.strings {
			matched[ys.id] = ys.re.Match(data)
		}
		if r.cond.eval(yaraCtx{matched: matched, data: data}) {
			hits = append(hits, Hit{Rule: r.ref, Detail: r.name})
		}
	}

	return hits
}

// HasFileRules reports whether any YARA rule is loaded.
func (s *Set) HasFileRules() bool { return len(s.yara) > 0 }

// ── conditions ──────────────────────────────────────────────────────────────

type yaraCtx struct {
	matched map[string]bool
	data    []byte
}

type yaraExpr interface{ eval(yaraCtx) bool }

type yAnd struct{ a, b yaraExpr }
type yOr struct{ a, b yaraExpr }
type yNot struct{ a yaraExpr }
type yStr struct{ id string }
type yOf struct {
	n   int // -1 any, -2 all
	ids []string
}
type yCmp struct {
	left  func(yaraCtx) (uint64, bool)
	op    string
	right uint64
}

func (e yAnd) eval(c yaraCtx) bool { return e.a.eval(c) && e.b.eval(c) }
func (e yOr) eval(c yaraCtx) bool  { return e.a.eval(c) || e.b.eval(c) }
func (e yNot) eval(c yaraCtx) bool { return !e.a.eval(c) }
func (e yStr) eval(c yaraCtx) bool { return c.matched[e.id] }
func (e yOf) eval(c yaraCtx) bool {
	n := 0
	for _, id := range e.ids {
		if c.matched[id] {
			n++
		}
	}
	switch e.n {
	case -1:
		return n > 0
	case -2:
		return n == len(e.ids)
	}

	return n >= e.n
}
func (e yCmp) eval(c yaraCtx) bool {
	v, ok := e.left(c)
	if !ok {
		return false
	}
	switch e.op {
	case "==":
		return v == e.right
	case "!=":
		return v != e.right
	case "<":
		return v < e.right
	case "<=":
		return v <= e.right
	case ">":
		return v > e.right
	case ">=":
		return v >= e.right
	}

	return false
}

var yaraToken = regexp.MustCompile(`\s*(\(|\)|==|!=|<=|>=|<|>|,|\$[A-Za-z0-9_]*\*?|[A-Za-z_][A-Za-z0-9_]*|0x[0-9A-Fa-f]+|\d+(?:KB|MB)?)`)

type yaraParser struct {
	toks []string
	pos  int
	ids  []string
}

func parseYaraCondition(cond string, strs []yaraString) (yaraExpr, error) {
	var toks []string
	rest := strings.TrimSpace(cond)
	for rest != "" {
		m := yaraToken.FindStringSubmatchIndex(rest)
		if m == nil || m[0] != 0 {
			return nil, fmt.Errorf("cannot read %q", firstLine(rest))
		}
		toks = append(toks, rest[m[2]:m[3]])
		rest = strings.TrimSpace(rest[m[1]:])
	}
	p := &yaraParser{toks: toks}
	for _, s := range strs {
		p.ids = append(p.ids, s.id)
	}
	e, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("unexpected %q", p.toks[p.pos])
	}

	return e, nil
}

func (p *yaraParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}

	return ""
}
func (p *yaraParser) next() string { t := p.peek(); p.pos++; return t }

func (p *yaraParser) or() (yaraExpr, error) {
	l, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.peek() == "or" {
		p.next()
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		l = yOr{l, r}
	}

	return l, nil
}

func (p *yaraParser) and() (yaraExpr, error) {
	l, err := p.unary()
	if err != nil {
		return nil, err
	}
	for p.peek() == "and" {
		p.next()
		r, err := p.unary()
		if err != nil {
			return nil, err
		}
		l = yAnd{l, r}
	}

	return l, nil
}

func (p *yaraParser) unary() (yaraExpr, error) {
	tok := p.next()
	switch {
	case tok == "":
		return nil, fmt.Errorf("ends early")
	case tok == "not":
		e, err := p.unary()
		if err != nil {
			return nil, err
		}

		return yNot{e}, nil
	case tok == "(":
		e, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.next() != ")" {
			return nil, fmt.Errorf("unclosed parenthesis")
		}

		return e, nil
	case tok == "true":
		return yOf{n: 0}, nil
	case tok == "any" || tok == "all" || isNumber(tok):
		return p.of(tok)
	case strings.HasPrefix(tok, "$"):
		if !p.known(tok) {
			return nil, fmt.Errorf("%s is not defined", tok)
		}

		return yStr{tok}, nil
	case tok == "filesize":
		return p.compare(func(c yaraCtx) (uint64, bool) { return uint64(len(c.data)), true })
	case strings.HasPrefix(tok, "uint") || strings.HasPrefix(tok, "int"):
		return p.readInt(tok)
	}

	return nil, fmt.Errorf("%q is not supported", tok)
}

func (p *yaraParser) known(id string) bool {
	for _, i := range p.ids {
		if i == id {
			return true
		}
	}

	return false
}

func (p *yaraParser) of(quant string) (yaraExpr, error) {
	if p.next() != "of" {
		return nil, fmt.Errorf("expected 'of' after %q", quant)
	}
	n := -1
	switch quant {
	case "all":
		n = -2
	case "any":
	default:
		n, _ = strconv.Atoi(quant)
	}
	var ids []string
	if p.peek() == "them" {
		p.next()
		ids = p.ids
	} else {
		if p.next() != "(" {
			return nil, fmt.Errorf("expected 'them' or a list after 'of'")
		}
		for {
			t := p.next()
			if !strings.HasPrefix(t, "$") {
				return nil, fmt.Errorf("expected a string in the list, got %q", t)
			}
			for _, id := range p.ids {
				if id == t || (strings.HasSuffix(t, "*") && strings.HasPrefix(id, strings.TrimSuffix(t, "*"))) {
					ids = append(ids, id)
				}
			}
			sep := p.next()
			if sep == ")" {
				break
			}
			if sep != "," {
				return nil, fmt.Errorf("expected ',' or ')' in the list")
			}
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("the set names no defined string")
	}

	return yOf{n: n, ids: ids}, nil
}

func (p *yaraParser) readInt(fn string) (yaraExpr, error) {
	width := map[string]int{"uint8": 1, "uint16": 2, "uint32": 4, "uint16be": 2, "uint32be": 4, "int8": 1, "int16": 2, "int32": 4}[fn]
	if width == 0 {
		return nil, fmt.Errorf("%q is not supported", fn)
	}
	big := strings.HasSuffix(fn, "be")
	if p.next() != "(" {
		return nil, fmt.Errorf("expected '(' after %s", fn)
	}
	off, err := parseYaraNumber(p.next())
	if err != nil {
		return nil, err
	}
	if p.next() != ")" {
		return nil, fmt.Errorf("only a constant offset is supported in %s()", fn)
	}

	return p.compare(func(c yaraCtx) (uint64, bool) {
		if off+uint64(width) > uint64(len(c.data)) {
			return 0, false
		}
		b := c.data[off : off+uint64(width)]
		var order binary.ByteOrder = binary.LittleEndian
		if big {
			order = binary.BigEndian
		}
		switch width {
		case 1:
			return uint64(b[0]), true
		case 2:
			return uint64(order.Uint16(b)), true
		}

		return uint64(order.Uint32(b)), true
	})
}

func (p *yaraParser) compare(left func(yaraCtx) (uint64, bool)) (yaraExpr, error) {
	op := p.next()
	switch op {
	case "==", "!=", "<", "<=", ">", ">=":
	default:
		return nil, fmt.Errorf("expected a comparison, got %q", op)
	}
	v, err := parseYaraNumber(p.next())
	if err != nil {
		return nil, err
	}

	return yCmp{left: left, op: op, right: v}, nil
}

func isNumber(s string) bool {
	_, err := parseYaraNumber(s)

	return err == nil
}

func parseYaraNumber(s string) (uint64, error) {
	mult := uint64(1)
	switch {
	case strings.HasSuffix(s, "KB"):
		mult, s = 1024, strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "MB"):
		mult, s = 1024*1024, strings.TrimSuffix(s, "MB")
	}
	v, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", s)
	}

	return v * mult, nil
}
