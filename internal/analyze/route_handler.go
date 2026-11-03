package analyze

// Handler body ranges for extracted routes.
//
// A finding is tied to a route as "inside the handler" only when the route says where the
// handler body is. These helpers find that range, and only when it can be read from this
// file: an inline function passed to the registration, a named function declared once in
// this file, a decorated Python function, a Spring method. A handler declared in another
// file, a token that does not resolve to exactly one declaration, or a body whose braces do
// not balance gives NO range. A wrong range puts a finding inside code that does not
// contain it, so every function here prefers returning "not found" to a guess.

import (
	"regexp"
	"strings"
)

var (
	jsArrowIdent = regexp.MustCompile(`^[A-Za-z_$][\w$]*\s*=>`)
	// A wrapper call around the real handler: asyncHandler(async (req, res) => {...}),
	// http.HandlerFunc(func(w, r) {...}).
	handlerWrapper = regexp.MustCompile(`^([A-Za-z_$][\w$]*)(?:\.[A-Za-z_$][\w$]*)*\s*\(`)
)

// scanBlock returns the index of the '}' that closes the '{' at src[open], or -1 when the
// braces never balance. Braces inside string, rune, raw string and template literals and
// inside comments do not count.
func scanBlock(src string, open int, language string) int {
	if open < 0 || open >= len(src) || src[open] != '{' {
		return -1
	}
	jvm := language == "java" || language == "kotlin"
	depth := 0
	for i := open; i < len(src); i++ {
		switch c := src[i]; c {
		case '/':
			if i+1 >= len(src) {
				continue
			}
			switch src[i+1] {
			case '/':
				nl := strings.IndexByte(src[i:], '\n')
				if nl < 0 {
					return -1
				}
				i += nl
			case '*':
				end := strings.Index(src[i+2:], "*/")
				if end < 0 {
					return -1
				}
				i += 2 + end + 1
			}
		case '"':
			if jvm && strings.HasPrefix(src[i:], `"""`) {
				end := strings.Index(src[i+3:], `"""`)
				if end < 0 {
					return -1
				}
				i += 3 + end + 2

				continue
			}
			i = skipString(src, i)
		case '\'':
			i = skipString(src, i)
		case '`':
			if language == "go" {
				end := strings.IndexByte(src[i+1:], '`')
				if end < 0 {
					return -1
				}
				i += 1 + end

				continue
			}
			end := skipTemplate(src, i, language)
			if end < 0 {
				return -1
			}
			i = end
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}

	return -1
}

// skipTemplate returns the index of the backtick closing the template literal at src[i],
// stepping over `${ ... }` expressions, or -1 when it never closes.
func skipTemplate(src string, i int, language string) int {
	for j := i + 1; j < len(src); j++ {
		switch src[j] {
		case '\\':
			j++
		case '`':
			return j
		case '$':
			if j+1 < len(src) && src[j+1] == '{' {
				end := scanBlock(src, j+1, language)
				if end < 0 {
					return -1
				}
				j = end
			}
		}
	}

	return -1
}

// argSpans returns the byte spans [start, end) of the top-level arguments of the call whose
// parentheses are at src[open] and src[closeIdx], each trimmed of white space.
func argSpans(src string, open, closeIdx int) [][2]int {
	if open < 0 || closeIdx <= open || closeIdx >= len(src) {
		return nil
	}
	var out [][2]int
	push := func(a, b int) {
		for a < b && isSpaceByte(src[a]) {
			a++
		}
		for b > a && isSpaceByte(src[b-1]) {
			b--
		}
		if a < b {
			out = append(out, [2]int{a, b})
		}
	}
	depth, last := 0, open+1
	for i := open + 1; i < closeIdx; i++ {
		switch src[i] {
		case '"', '\'', '`':
			i = skipString(src, i)
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				push(last, i)
				last = i + 1
			}
		}
	}
	push(last, closeIdx)

	return out
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// hasWord reports whether s starts with the whole word w.
func hasWord(s, w string) bool {
	return strings.HasPrefix(s, w) && (len(s) == len(w) || !isIdentByte(s[len(w)]))
}

// inlineHandlerSpan finds the function written inline as the last argument of the route call
// whose parentheses are at src[open] and src[closeIdx]. It returns the byte offset where the
// function starts and the offset of the last byte of its body.
func inlineHandlerSpan(src string, open, closeIdx int, language string) (start, end int, ok bool) {
	args := argSpans(src, open, closeIdx)
	if len(args) < 2 {
		return 0, 0, false
	}
	last := args[len(args)-1]

	return funcLiteralSpan(src, last[0], last[1], language, 0)
}

// funcLiteralSpan reads a function literal in src[s:e], or one wrapper call around it.
func funcLiteralSpan(src string, s, e int, language string, depth int) (start, end int, ok bool) {
	var endOff int
	if language == "go" {
		endOff, ok = goFuncLiteralEnd(src, s, e)
	} else {
		endOff, ok = jsFuncLiteralEnd(src, s, e, language)
	}
	if ok {
		return s, endOff, true
	}
	if depth >= 2 {
		return 0, 0, false
	}
	m := handlerWrapper.FindStringSubmatchIndex(src[s:e])
	if m == nil {
		return 0, 0, false
	}
	switch src[s+m[2] : s+m[3]] {
	case "func", "function", "async":
		return 0, 0, false
	}
	open := s + m[1] - 1
	if matchBracket(src, open) != e-1 {
		return 0, 0, false
	}
	inner := argSpans(src, open, e-1)
	if len(inner) == 0 {
		return 0, 0, false
	}
	last := inner[len(inner)-1]

	return funcLiteralSpan(src, last[0], last[1], language, depth+1)
}

// goFuncLiteralEnd reads `func(...) ... { body }` filling src[s:e] and returns the offset of
// the body's closing brace.
func goFuncLiteralEnd(src string, s, e int) (int, bool) {
	if !hasWord(src[s:e], "func") {
		return 0, false
	}
	p := s + len("func")
	for p < e && isSpaceByte(src[p]) {
		p++
	}
	if p >= e || src[p] != '(' {
		return 0, false
	}
	bodyOpen := goBodyOpen(src, p)
	if bodyOpen < 0 || bodyOpen >= e {
		return 0, false
	}
	end := scanBlock(src, bodyOpen, "go")
	if end < 0 || end >= e {
		return 0, false
	}

	return end, true
}

// jsFuncLiteralEnd reads `function (…) {…}`, `(…) => {…}`, `x => {…}` or an arrow with an
// expression body, optionally `async`, filling src[s:e]. It returns the offset of the last
// byte of the body.
func jsFuncLiteralEnd(src string, s, e int, language string) (int, bool) {
	p := s
	if hasWord(src[p:e], "async") {
		p += len("async")
		for p < e && isSpaceByte(src[p]) {
			p++
		}
	}
	if p >= e {
		return 0, false
	}
	switch {
	case hasWord(src[p:e], "function"):
		q := strings.IndexByte(src[p:e], '(')
		if q < 0 {
			return 0, false
		}
		pc := matchBracket(src, p+q)
		if pc < 0 || pc >= e {
			return 0, false
		}
		bo := strings.IndexByte(src[pc:e], '{')
		if bo < 0 {
			return 0, false
		}
		end := scanBlock(src, pc+bo, language)
		if end < 0 || end >= e {
			return 0, false
		}

		return end, true
	case src[p] == '(':
		pc := matchBracket(src, p)
		if pc < 0 || pc >= e {
			return 0, false
		}
		arrow := strings.Index(src[pc:e], "=>")
		if arrow < 0 {
			return 0, false
		}
		// Only a return type annotation may sit between the parameters and the arrow.
		between := strings.TrimSpace(src[pc+1 : pc+arrow])
		if between != "" && !strings.HasPrefix(between, ":") {
			return 0, false
		}

		return arrowBodyEnd(src, pc+arrow+2, e, language)
	default:
		m := jsArrowIdent.FindStringIndex(src[p:e])
		if m == nil {
			return 0, false
		}

		return arrowBodyEnd(src, p+m[1], e, language)
	}
}

// arrowBodyEnd reads what follows `=>` in src[from:e]: a braced body, or an expression that
// runs to the end of the argument.
func arrowBodyEnd(src string, from, e int, language string) (int, bool) {
	for from < e && isSpaceByte(src[from]) {
		from++
	}
	if from >= e {
		return 0, false
	}
	if src[from] != '{' {
		return e - 1, true
	}
	end := scanBlock(src, from, language)
	if end < 0 || end >= e {
		return 0, false
	}

	return end, true
}

// jsNamedHandlerSpan finds the one `function name(` or `const name = … =>` declaration of a
// plain identifier in the file and returns the byte span of the whole declaration. A dotted
// handler (`ctrl.list`) is a member of something else and is never matched by its last
// segment.
func jsNamedHandlerSpan(src, name, language string) (start, end int, ok bool) {
	if !jsIdent.MatchString(name) {
		return 0, 0, false
	}
	q := regexp.QuoteMeta(name)
	forms := []*regexp.Regexp{
		regexp.MustCompile(`(?m)(?:^|[^\w$.])(?:async\s+)?function\s*\*?\s*` + q + `\s*\(`),
		regexp.MustCompile(`(?m)(?:const|let|var)\s+` + q + `\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*(?::\s*[\w<>\[\], ]+)?\s*=>|[A-Za-z_$][\w$]*\s*=>)`),
	}
	var heads [][]int
	var isFunc []bool
	for i, re := range forms {
		for _, h := range re.FindAllStringIndex(src, -1) {
			heads = append(heads, h)
			isFunc = append(isFunc, i == 0 || strings.HasSuffix(src[h[0]:h[1]], "function"))
		}
	}
	if len(heads) != 1 {
		return 0, 0, false
	}
	h := heads[0]
	st := h[0]
	for st < h[1] && !isIdentByte(src[st]) {
		st++
	}

	if isFunc[0] {
		var pOpen int
		if strings.HasSuffix(src[h[0]:h[1]], "(") {
			pOpen = h[1] - 1
		} else {
			q := strings.IndexByte(src[h[1]:], '(')
			if q < 0 {
				return 0, 0, false
			}
			pOpen = h[1] + q
		}
		pc := matchBracket(src, pOpen)
		if pc < 0 {
			return 0, 0, false
		}
		bo := strings.IndexAny(src[pc:], "{;")
		if bo < 0 || src[pc+bo] != '{' {
			return 0, 0, false
		}
		endOff := scanBlock(src, pc+bo, language)
		if endOff < 0 {
			return 0, 0, false
		}

		return st, endOff, true
	}

	from := h[1]
	for from < len(src) && isSpaceByte(src[from]) {
		from++
	}
	if from >= len(src) {
		return 0, 0, false
	}
	if src[from] == '{' {
		endOff := scanBlock(src, from, language)
		if endOff < 0 {
			return 0, 0, false
		}

		return st, endOff, true
	}
	endOff := jsExprEnd(src, from)
	if endOff < 0 {
		return 0, 0, false
	}

	return st, endOff, true
}

// jsExprEnd returns the offset of the last byte of the expression statement starting at
// src[from]: it ends at a top-level `;`, or at a newline that the next line does not
// continue. -1 when the brackets do not balance.
func jsExprEnd(src string, from int) int {
	depth, last := 0, from
	for i := from; i < len(src); i++ {
		c := src[i]
		switch c {
		case '"', '\'', '`':
			i = skipString(src, i)
			last = i
		case '(', '[', '{':
			depth++
			last = i
		case ')', ']', '}':
			depth--
			if depth < 0 {
				return last
			}
			last = i
		case ';':
			if depth == 0 {
				return last
			}
		case '\n':
			if depth == 0 {
				j := i + 1
				for j < len(src) && isSpaceByte(src[j]) {
					j++
				}
				if j >= len(src) || !strings.ContainsRune(".?:&|+-*/,", rune(src[j])) {
					return last
				}
			}
		default:
			if !isSpaceByte(c) {
				last = i
			}
		}
	}
	if depth != 0 {
		return -1
	}

	return last
}

// pyScan carries the state that makes a Python line a continuation of the previous one.
type pyScan struct {
	depth  int
	triple string
	cont   bool
}

func (p *pyScan) open() bool { return p.depth > 0 || p.triple != "" || p.cont }

// line advances the state over one source line.
func (p *pyScan) line(l string) {
	p.cont = false
	for i := 0; i < len(l); i++ {
		if p.triple != "" {
			if strings.HasPrefix(l[i:], p.triple) {
				i += 2
				p.triple = ""
			}

			continue
		}
		switch c := l[i]; c {
		case '#':
			return
		case '"', '\'':
			if strings.HasPrefix(l[i:], strings.Repeat(string(c), 3)) {
				p.triple = strings.Repeat(string(c), 3)
				i += 2

				continue
			}
			for i++; i < len(l) && l[i] != c; i++ {
				if l[i] == '\\' {
					i++
				}
			}
		case '(', '[', '{':
			p.depth++
		case ')', ']', '}':
			if p.depth > 0 {
				p.depth--
			}
		case '\\':
			if i == len(l)-1 {
				p.cont = true
			}
		}
	}
}

// pyBlockEnd is the last non-blank line of the block whose header is on defLine (1-based):
// every following line indented deeper than the header belongs to it, and so does any line
// that continues an open bracket, a triple-quoted string or a backslash, whatever its
// indent. Blank and comment-only lines never end a block and never extend it.
func pyBlockEnd(lines []string, defLine int) int {
	if defLine < 1 || defLine > len(lines) {
		return 0
	}
	header := lines[defLine-1]
	indent := len(header) - len(strings.TrimLeft(header, " \t"))
	var st pyScan
	st.line(header)
	end := defLine
	for i := defLine; i < len(lines); i++ {
		l := lines[i]
		t := strings.TrimSpace(l)
		if st.open() {
			if t != "" {
				end = i + 1
			}
			st.line(l)

			continue
		}
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if len(l)-len(strings.TrimLeft(l, " \t")) <= indent {
			break
		}
		end = i + 1
		st.line(l)
	}

	return end
}
