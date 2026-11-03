package analyze

// Route extraction for the cross-repo contract collector.
//
// A route is found by pattern, not by understanding the framework, so everything here is
// best effort and biased towards saying less: a mount prefix is applied only when the
// router that carries the route is mounted in the SAME file, and a router whose mount
// cannot be seen keeps its own relative path rather than a guessed one. A wrong prefix
// invents an endpoint nobody serves; a missing one only loses precision.
//
// Every route also carries where it lives (start, end lines), so a finding whose SARIF
// region sits inside the handler can be tied to the route, and the handler token, so a
// reader can tell two routes registered at one path apart.

import (
	"crypto/sha1"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

// route is one served endpoint found in a source file.
type route struct {
	method string
	// path is the full path, mount prefix included.
	path string
	// handler is the handler as written ("h.List", "listUsers", a Python function name),
	// empty for an inline function.
	handler string
	// prefix is the resolved mount prefix, empty when none was found.
	prefix string
	// start and end are 1-based lines: the handler when it was found in this file, else
	// the registration. 0 when unknown.
	start, end int
	// registered is the line of the registration (call, decorator or annotation).
	registered int
}

var (
	// Go: chi, gin, echo, fiber, mux, net/http. Both Get and GET spell it.
	goRouteCall = regexp.MustCompile(`\.(Get|GET|Post|POST|Put|PUT|Patch|PATCH|Delete|DELETE|Head|HEAD|Options|OPTIONS|Any|Handle|HandleFunc)\(\s*"([^"]+)"`)
	// Express, Fastify, Koa.
	jsRouteCall = regexp.MustCompile(`\.(get|post|put|patch|delete|all)\(\s*['"` + "`" + `]([^'"` + "`" + `]+)`)
	// FastAPI, Flask: @router.get("/x"), @bp.route("/x"). The path may be empty when the
	// router carries a prefix.
	pyRouteDeco = regexp.MustCompile(`@([A-Za-z_]\w*)\.(get|post|put|patch|delete|route)\(\s*['"]([^'"]*)`)
	// Spring.
	javaRouteAnno = regexp.MustCompile(`@(Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:(?:value|path)\s*=\s*)?"([^"]+)"`)

	goGroupDecl     = regexp.MustCompile(`([A-Za-z_]\w*)\s*(?::=|=)\s*([A-Za-z_]\w*)\.Group\(\s*"([^"]*)"`)
	goSubrouterDecl = regexp.MustCompile(`([A-Za-z_]\w*)\s*(?::=|=)\s*([A-Za-z_]\w*)\.PathPrefix\(\s*"([^"]+)"\s*\)\.Subrouter\(\)`)
	goRouteScope    = regexp.MustCompile(`([A-Za-z_]\w*)\.Route\(\s*"([^"]*)"\s*,\s*func\(\s*([A-Za-z_]\w*)\s+[\w.*]+\s*\)\s*\{`)
	goMountCall     = regexp.MustCompile(`([A-Za-z_]\w*)\.Mount\(\s*"([^"]*)"\s*,\s*([A-Za-z_]\w*)(\(\))?`)
	goFuncDecl      = regexp.MustCompile(`(?m)^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(`)
	goIdentExpr     = regexp.MustCompile(`^[A-Za-z_]\w*(\.[A-Za-z_]\w*)*$`)

	jsMountCall     = regexp.MustCompile(`([A-Za-z_$][\w$]*)\.use\(\s*['"` + "`" + `](/[^'"` + "`" + `]*)['"` + "`" + `]\s*,`)
	jsKoaPrefixDecl = regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+Router\(\s*\{[^}]*prefix\s*:\s*['"` + "`" + `]([^'"` + "`" + `]+)`)
	jsRoutesCall    = regexp.MustCompile(`^([A-Za-z_$][\w$]*)\.routes\(\)$`)
	jsIdent         = regexp.MustCompile(`^[A-Za-z_$][\w$]*$`)
	jsIdentExpr     = regexp.MustCompile(`^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$`)

	pyRouterDecl  = regexp.MustCompile(`([A-Za-z_]\w*)\s*=\s*(APIRouter|Blueprint)\(`)
	pyIncludeCall = regexp.MustCompile(`([A-Za-z_]\w*)\.(include_router|register_blueprint)\(\s*([A-Za-z_][\w.]*)`)
	pyDefLine     = regexp.MustCompile(`^([ \t]*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`)
	pyPrefixKw    = regexp.MustCompile(`\bprefix\s*=\s*['"]([^'"]*)['"]`)
	pyURLPrefixKw = regexp.MustCompile(`\burl_prefix\s*=\s*['"]([^'"]*)['"]`)
	pyMethodsKw   = regexp.MustCompile(`methods\s*=\s*[\[(]([^\])]*)[\])]`)
	pyQuoted      = regexp.MustCompile(`['"]([A-Za-z]+)['"]`)

	javaClassMapping = regexp.MustCompile(`(?s)@RequestMapping\(\s*(?:(?:value|path)\s*=\s*)?"([^"]*)"[^)]*\)\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:(?:public|protected|private|abstract|final|open|data|sealed)\s+)*(?:class|interface)\s+\w+[^{]*\{`)
	javaMethodName   = regexp.MustCompile(`(?s)\A\s*(?:@\w+(?:\((?:[^()]|\([^()]*\))*\))?\s*)*(?:(?:public|protected|private|static|final|abstract|override|suspend|open)\s+)*(?:fun\s+)?(?:[\w<>\[\],.?]+\s+)*?([A-Za-z_]\w*)\s*\(`)
)

// extractRoutes returns the routes a source file serves, with mount prefixes applied where
// the mount is visible in the file. src is comment-stripped with its lines intact.
func extractRoutes(src, language string) []route {
	switch language {
	case "go":
		return extractGoRoutes(src)
	case "javascript", "typescript", "tsx":
		return extractJSRoutes(src)
	case "python":
		return extractPyRoutes(src)
	case "java", "kotlin":
		return extractJavaRoutes(src)
	}

	return nil
}

// ---- helpers ----------------------------------------------------------------------------

// lineIndex maps byte offsets to 1-based line numbers.
type lineIndex []int

func newLineIndex(src string) lineIndex {
	idx := lineIndex{0}
	for i := 0; i < len(src); i++ {
		if src[i] == '\n' {
			idx = append(idx, i+1)
		}
	}

	return idx
}

func (l lineIndex) line(off int) int {
	return sort.Search(len(l), func(i int) bool { return l[i] > off })
}

// skipString returns the index of the quote closing the string literal that opens at
// src[i], or len(src)-1 when it never closes. A `"` or `'` literal ends at a newline.
func skipString(src string, i int) int {
	c := src[i]
	j := i + 1
	for j < len(src) && src[j] != c {
		if src[j] == '\\' && c != '`' {
			j++
		} else if src[j] == '\n' && c != '`' {
			return j - 1
		}
		j++
	}
	if j >= len(src) {
		return len(src) - 1
	}

	return j
}

// matchBracket returns the index of the bracket closing the one at src[open], skipping
// string literals, or -1.
func matchBracket(src string, open int) int {
	if open < 0 || open >= len(src) {
		return -1
	}
	var closer byte
	switch src[open] {
	case '(':
		closer = ')'
	case '{':
		closer = '}'
	case '[':
		closer = ']'
	default:
		return -1
	}
	opener := src[open]
	depth := 0
	for i := open; i < len(src); i++ {
		switch c := src[i]; c {
		case '"', '\'', '`':
			i = skipString(src, i)
		case opener:
			depth++
		case closer:
			depth--
			if depth == 0 {
				return i
			}
		}
	}

	return -1
}

// splitArgs splits the text between a call's parentheses at top-level commas.
func splitArgs(s string) []string {
	var out []string
	depth, last := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"', '\'', '`':
			i = skipString(s, i)
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[last:i]))
				last = i + 1
			}
		}
	}
	if tail := strings.TrimSpace(s[last:]); tail != "" {
		out = append(out, tail)
	}

	return out
}

// receiverBefore reads the identifier a method is called on, from the dot at src[dot]. It
// steps over a trailing `.With(...)` or `.Use(...)` so `r.With(mw).Get(` is still `r`. A
// receiver that is itself a call result or a chain returns "".
func receiverBefore(src string, dot int) string {
	i := dot
	if i > 0 && src[i-1] == ')' {
		open := matchBracketBack(src, i-1)
		if open < 0 {
			return ""
		}
		j := open
		for j > 0 && isIdentByte(src[j-1]) {
			j--
		}
		name := src[j:open]
		if (name != "With" && name != "Use") || j == 0 || src[j-1] != '.' {
			return ""
		}
		i = j - 1
	}
	j := i
	for j > 0 && isIdentByte(src[j-1]) {
		j--
	}
	if j == i {
		return ""
	}
	// A dotted receiver (`s.router.Get`) is a field, not a variable we can follow.
	if j > 0 && src[j-1] == '.' {
		return ""
	}

	return src[j:i]
}

func matchBracketBack(src string, closeIdx int) int {
	depth := 0
	for i := closeIdx; i >= 0; i-- {
		switch src[i] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				return i
			}
		}
	}

	return -1
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func joinPrefix(prefix, p string) string {
	switch {
	case prefix == "":
		return p
	case p == "":
		return prefix
	case prefix == "/":
		return p
	}

	return strings.TrimRight(prefix, "/") + "/" + strings.TrimLeft(p, "/")
}

func capStrings(in []string, n int) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) == n {
			break
		}
	}
	if len(out) == 0 {
		return []string{""}
	}

	return out
}

func collapseSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}

	return s
}

// routerNode is one router (or group) that carries a prefix, declared at off inside the
// function numbered fn (0 outside any function).
type routerNode struct {
	name   string
	parent string
	prefix string
	off    int
	fn     int
}

// routerScope is a router name valid for a byte range only (a chi Route closure).
type routerScope struct {
	name       string
	parent     string
	prefix     string
	start, end int
	parentOff  int
}

// mountTable answers "what prefixes does the router named name carry at offset off".
type mountTable struct {
	decls  []routerNode
	scopes []routerScope
	// fnAt numbers the function an offset sits in, so a variable declared in one function
	// is never taken for a same-named variable in another. Nil means one scope.
	fnAt func(off int) int
	// anyOrder reads every mount of a name wherever it sits in the file (JavaScript mounts
	// routers after the routes that use them, and one router can be mounted twice).
	anyOrder bool
}

func (t *mountTable) fn(off int) int {
	if t.fnAt == nil {
		return 0
	}

	return t.fnAt(off)
}

func (t *mountTable) prefixes(name string, off int, depth int) []string {
	if name == "" || depth > 6 {
		return []string{""}
	}
	var best *routerScope
	for i := range t.scopes {
		s := &t.scopes[i]
		if s.name == name && off >= s.start && off <= s.end && (best == nil || s.start > best.start) {
			best = s
		}
	}
	if best != nil {
		var out []string
		for _, pp := range t.prefixes(best.parent, best.parentOff, depth+1) {
			out = append(out, joinPrefix(pp, best.prefix))
		}

		return out
	}
	if t.anyOrder {
		var out []string
		for i := range t.decls {
			n := &t.decls[i]
			if n.name != name {
				continue
			}
			for _, pp := range t.prefixes(n.parent, n.off, depth+1) {
				out = append(out, joinPrefix(pp, n.prefix))
			}
		}
		if len(out) == 0 {
			return []string{""}
		}

		return out
	}
	var d *routerNode
	for i := range t.decls {
		n := &t.decls[i]
		if n.name == name && n.off <= off && n.fn == t.fn(off) && (d == nil || n.off > d.off) {
			d = n
		}
	}
	if d == nil {
		return []string{""}
	}
	var out []string
	for _, pp := range t.prefixes(d.parent, d.off, depth+1) {
		out = append(out, joinPrefix(pp, d.prefix))
	}

	return out
}

// ---- Go ---------------------------------------------------------------------------------

type funcScope struct {
	name       string
	start, end int
}

func extractGoRoutes(src string) []route {
	lines := newLineIndex(src)
	funcs := goFuncScopes(src)
	fnIndex := func(off int) int {
		for i := range funcs {
			if off >= funcs[i].start && off <= funcs[i].end {
				return i + 1
			}
		}

		return 0
	}
	tbl := &mountTable{fnAt: fnIndex}
	for _, re := range []*regexp.Regexp{goGroupDecl, goSubrouterDecl} {
		for _, m := range re.FindAllStringSubmatchIndex(src, -1) {
			tbl.decls = append(tbl.decls, routerNode{
				name: src[m[2]:m[3]], parent: src[m[4]:m[5]], prefix: src[m[6]:m[7]], off: m[0], fn: fnIndex(m[0]),
			})
		}
	}
	for _, m := range goRouteScope.FindAllStringSubmatchIndex(src, -1) {
		open := m[1] - 1 // the '{' the pattern ends on
		end := matchBracket(src, open)
		if end < 0 {
			continue
		}
		tbl.scopes = append(tbl.scopes, routerScope{
			name: src[m[6]:m[7]], parent: src[m[2]:m[3]], prefix: src[m[4]:m[5]],
			start: open, end: end, parentOff: m[0],
		})
	}
	// Mount("/p", child) and Mount("/p", build()): the child is a variable, or the function
	// that builds the router, and carries the prefix.
	funcMounts := map[string][]routerNode{}
	for _, m := range goMountCall.FindAllStringSubmatchIndex(src, -1) {
		parent, prefix, child := src[m[2]:m[3]], src[m[4]:m[5]], src[m[6]:m[7]]
		node := routerNode{name: child, parent: parent, prefix: prefix, off: m[0], fn: fnIndex(m[0])}
		if m[8] >= 0 { // child()
			funcMounts[child] = append(funcMounts[child], node)

			continue
		}
		tbl.decls = append(tbl.decls, node)
	}

	var out []route
	for _, m := range goRouteCall.FindAllStringSubmatchIndex(src, -1) {
		method, p := src[m[2]:m[3]], src[m[4]:m[5]]
		if !strings.HasPrefix(p, "/") {
			continue
		}
		recv := receiverBefore(src, m[0])
		closeIdx := matchBracket(src, m[0]+1+len(method))

		bases := []string{""}
		if i := fnIndex(m[0]); i > 0 && len(funcMounts[funcs[i-1].name]) > 0 {
			// The router is built by a function the file mounts.
			bases = nil
			for _, mt := range funcMounts[funcs[i-1].name] {
				for _, pp := range tbl.prefixes(mt.parent, mt.off, 0) {
					bases = append(bases, joinPrefix(pp, mt.prefix))
				}
			}
		}
		var prefixes []string
		for _, b := range bases {
			for _, local := range tbl.prefixes(recv, m[0], 0) {
				prefixes = append(prefixes, joinPrefix(b, local))
			}
		}
		prefixes = capStrings(prefixes, 4)

		handler, inline, ident := goHandler(src, m[5], closeIdx)
		reg := lines.line(m[0])
		start, end := reg, reg
		if closeIdx > 0 {
			end = lines.line(closeIdx)
		}
		if !inline && ident != "" {
			if s, e, ok := goHandlerDecl(src, lines, funcs, ident); ok {
				start, end = s, e
			}
		}
		for _, pp := range prefixes {
			out = append(out, route{
				method: strings.ToUpper(method), path: joinPrefix(pp, p), handler: handler,
				prefix: pp, start: start, end: end, registered: reg,
			})
		}
	}

	return out
}

// goFuncScopes lists top-level function declarations with their body extents.
func goFuncScopes(src string) []funcScope {
	var out []funcScope
	for _, m := range goFuncDecl.FindAllStringSubmatchIndex(src, -1) {
		bodyOpen := goBodyOpen(src, m[1]-1)
		if bodyOpen < 0 {
			continue
		}
		if end := matchBracket(src, bodyOpen); end > 0 {
			out = append(out, funcScope{name: src[m[2]:m[3]], start: m[0], end: end})
		}
	}

	return out
}

// goBodyOpen finds the '{' that opens a function body, given the '(' that opens its
// parameters. It steps over the parameter list and any result type, but not over
// `struct{}` or `interface{}` inside it. -1 for a declaration with no body.
func goBodyOpen(src string, paramsOpen int) int {
	i := matchBracket(src, paramsOpen)
	if i < 0 {
		return -1
	}
	for j := i + 1; j < len(src); j++ {
		switch src[j] {
		case '{':
			head := strings.TrimRight(src[:j], " \t")
			if strings.HasSuffix(head, "struct") || strings.HasSuffix(head, "interface") {
				end := matchBracket(src, j)
				if end < 0 {
					return -1
				}
				j = end

				continue
			}

			return j
		case '(':
			end := matchBracket(src, j)
			if end < 0 {
				return -1
			}
			j = end
		case '\n':
			// A result type never spans a blank line; a declaration with no body ends here.
			if j+1 < len(src) && src[j+1] == '\n' {
				return -1
			}
		}
	}

	return -1
}

// goHandler reads the handler out of a route call: the last argument after the path.
// inline is true for a func literal; ident is set when the handler is a plain identifier
// or selector that may be declared in this file.
func goHandler(src string, afterPath, closeIdx int) (token string, inline bool, ident string) {
	if closeIdx < 0 || afterPath > closeIdx {
		return "", false, ""
	}
	rest := strings.TrimSpace(strings.TrimPrefix(src[afterPath:closeIdx], `"`))
	args := splitArgs(strings.TrimPrefix(rest, ","))
	if len(args) == 0 {
		return "", false, ""
	}
	last := strings.TrimSpace(args[len(args)-1])
	if strings.HasPrefix(last, "func(") || strings.HasPrefix(last, "func (") {
		return "", true, ""
	}
	token = clip(collapseSpace(last), 80)
	if goIdentExpr.MatchString(last) {
		return token, false, last
	}

	return token, false, ""
}

// goHandlerDecl finds `func Name(` or `func (r T) Name(` for the last segment of ident and
// returns its line extent when there is exactly one declaration in the file.
func goHandlerDecl(src string, lines lineIndex, _ []funcScope, ident string) (start, end int, ok bool) {
	name := ident
	if i := strings.LastIndex(ident, "."); i >= 0 {
		name = ident[i+1:]
	}
	var found []int
	n := 0
	for _, m := range goFuncDecl.FindAllStringSubmatchIndex(src, -1) {
		if src[m[2]:m[3]] == name {
			found = m
			n++
		}
	}
	if n != 1 {
		return 0, 0, false
	}
	bodyOpen := goBodyOpen(src, found[1]-1)
	if bodyOpen < 0 {
		return 0, 0, false
	}
	closeIdx := matchBracket(src, bodyOpen)
	if closeIdx < 0 {
		return 0, 0, false
	}

	return lines.line(found[0]), lines.line(closeIdx), true
}

// ---- JavaScript / TypeScript ------------------------------------------------------------

func extractJSRoutes(src string) []route {
	lines := newLineIndex(src)
	tbl := &mountTable{anyOrder: true}
	for _, m := range jsMountCall.FindAllStringSubmatchIndex(src, -1) {
		open := m[0] + strings.Index(src[m[0]:m[1]], "(")
		closeIdx := matchBracket(src, open)
		if closeIdx < 0 {
			continue
		}
		args := splitArgs(src[open+1 : closeIdx])
		if len(args) < 2 {
			continue
		}
		child := strings.TrimSpace(args[len(args)-1])
		if cm := jsRoutesCall.FindStringSubmatch(child); cm != nil {
			child = cm[1]
		}
		if !jsIdent.MatchString(child) {
			continue
		}
		tbl.decls = append(tbl.decls, routerNode{name: child, parent: src[m[2]:m[3]], prefix: src[m[4]:m[5]], off: m[0]})
	}
	for _, m := range jsKoaPrefixDecl.FindAllStringSubmatchIndex(src, -1) {
		tbl.decls = append(tbl.decls, routerNode{name: src[m[2]:m[3]], prefix: src[m[4]:m[5]], off: m[0]})
	}

	var out []route
	for _, m := range jsRouteCall.FindAllStringSubmatchIndex(src, -1) {
		method, p := src[m[2]:m[3]], src[m[4]:m[5]]
		if !strings.HasPrefix(p, "/") {
			continue
		}
		recv := receiverBefore(src, m[0])
		closeIdx := matchBracket(src, m[0]+1+len(method))
		reg := lines.line(m[0])
		start, end := reg, reg
		if closeIdx > 0 {
			end = lines.line(closeIdx)
		}
		handler, inline, ident := jsHandler(src, m[5], closeIdx)
		if !inline && ident != "" {
			if s, e, ok := jsHandlerDecl(src, lines, ident); ok {
				start, end = s, e
			}
		}
		for _, pp := range capStrings(tbl.prefixes(recv, m[0], 0), 4) {
			out = append(out, route{
				method: strings.ToUpper(method), path: joinPrefix(pp, p), handler: handler,
				prefix: pp, start: start, end: end, registered: reg,
			})
		}
	}

	return out
}

func jsHandler(src string, afterPath, closeIdx int) (token string, inline bool, ident string) {
	if closeIdx < 0 || afterPath > closeIdx {
		return "", false, ""
	}
	rest := src[afterPath:closeIdx]
	// Drop the rest of the path literal.
	if i := strings.IndexAny(rest, "'\"`"); i >= 0 {
		rest = rest[i+1:]
	}
	rest = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), ","))
	args := splitArgs(rest)
	if len(args) == 0 {
		return "", false, ""
	}
	last := strings.TrimSpace(args[len(args)-1])
	if strings.Contains(last, "=>") || strings.HasPrefix(last, "function") || strings.HasPrefix(last, "async") {
		return "", true, ""
	}
	token = clip(collapseSpace(last), 80)
	if jsIdentExpr.MatchString(last) {
		return token, false, last
	}

	return token, false, ""
}

// jsHandlerDecl finds `function name(` or `const name = (…) =>` for the last segment of
// ident, when there is exactly one in the file, and returns its extent.
func jsHandlerDecl(src string, lines lineIndex, ident string) (start, end int, ok bool) {
	name := ident
	if i := strings.LastIndex(ident, "."); i >= 0 {
		name = ident[i+1:]
	}
	q := regexp.QuoteMeta(name)
	forms := []*regexp.Regexp{
		regexp.MustCompile(`(?m)(?:^|[^\w$.])(?:async\s+)?function\s*\*?\s*` + q + `\s*\(`),
		regexp.MustCompile(`(?m)(?:const|let|var)\s+` + q + `\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*(?::\s*[\w<>\[\], ]+)?\s*=>|[A-Za-z_$][\w$]*\s*=>)`),
	}
	var heads [][]int
	for _, re := range forms {
		heads = append(heads, re.FindAllStringIndex(src, -1)...)
	}
	if len(heads) != 1 {
		return 0, 0, false
	}
	h := heads[0]
	open := strings.Index(src[h[1]-1:], "{")
	if open < 0 {
		return 0, 0, false
	}
	closeIdx := matchBracket(src, h[1]-1+open)
	if closeIdx < 0 {
		return 0, 0, false
	}

	st := h[0]
	for st < h[1] && (src[st] == '\n' || src[st] == ' ' || src[st] == '\t') {
		st++
	}

	return lines.line(st), lines.line(closeIdx), true
}

// ---- Python -----------------------------------------------------------------------------

type pyRouter struct {
	kind     string // APIRouter | Blueprint
	own      string
	includes []pyInclude
}

type pyInclude struct {
	parent    string
	prefix    string
	hasPrefix bool
}

func extractPyRoutes(src string) []route {
	lines := newLineIndex(src)
	routers := map[string]*pyRouter{}
	for _, m := range pyRouterDecl.FindAllStringSubmatchIndex(src, -1) {
		name, kind := src[m[2]:m[3]], src[m[4]:m[5]]
		closeIdx := matchBracket(src, m[1]-1)
		if closeIdx < 0 {
			continue
		}
		r := &pyRouter{kind: kind}
		kw := pyPrefixKw
		if kind == "Blueprint" {
			kw = pyURLPrefixKw
		}
		if pm := kw.FindStringSubmatch(src[m[1]-1 : closeIdx+1]); pm != nil {
			r.own = pm[1]
		}
		routers[name] = r
	}
	for _, m := range pyIncludeCall.FindAllStringSubmatchIndex(src, -1) {
		parent, fn, child := src[m[2]:m[3]], src[m[4]:m[5]], src[m[6]:m[7]]
		r := routers[child]
		if r == nil {
			continue
		}
		open := m[0] + strings.Index(src[m[0]:], "(")
		closeIdx := matchBracket(src, open)
		if closeIdx < 0 {
			continue
		}
		kw := pyPrefixKw
		if fn == "register_blueprint" {
			kw = pyURLPrefixKw
		}
		inc := pyInclude{parent: parent}
		if pm := kw.FindStringSubmatch(src[open : closeIdx+1]); pm != nil {
			inc.prefix, inc.hasPrefix = pm[1], true
		}
		r.includes = append(r.includes, inc)
	}

	var prefixesOf func(name string, depth int) []string
	prefixesOf = func(name string, depth int) []string {
		r := routers[name]
		if r == nil || depth > 6 {
			return []string{""}
		}
		if len(r.includes) == 0 {
			return []string{r.own}
		}
		var out []string
		for _, inc := range r.includes {
			for _, pp := range prefixesOf(inc.parent, depth+1) {
				if r.kind == "Blueprint" && inc.hasPrefix {
					// Flask: the registration's url_prefix replaces the blueprint's own.
					out = append(out, joinPrefix(pp, inc.prefix))

					continue
				}
				out = append(out, joinPrefix(joinPrefix(pp, inc.prefix), r.own))
			}
		}

		return out
	}

	srcLines := strings.Split(src, "\n")
	var out []route
	for _, m := range pyRouteDeco.FindAllStringSubmatchIndex(src, -1) {
		recv, method, p := src[m[2]:m[3]], src[m[4]:m[5]], src[m[6]:m[7]]
		prefixes := []string{""}
		if routers[recv] != nil {
			prefixes = capStrings(prefixesOf(recv, 0), 4)
		}
		methods := []string{strings.ToUpper(method)}
		if method == "route" {
			// Flask names the verbs in the decorator: methods=["POST"].
			if closeIdx := matchBracket(src, m[0]+strings.Index(src[m[0]:], "(")); closeIdx > 0 {
				if mm := pyMethodsKw.FindStringSubmatch(src[m[0]:closeIdx]); mm != nil {
					var named []string
					for _, q := range pyQuoted.FindAllStringSubmatch(mm[1], -1) {
						named = append(named, strings.ToUpper(q[1]))
					}
					if len(named) > 0 {
						methods = named
					}
				}
			}
		}
		reg := lines.line(m[0])
		handler, defLine := pyHandlerAfter(srcLines, reg)
		start, end := reg, reg
		if defLine > 0 {
			end = pyBlockEnd(srcLines, defLine)
		}
		for _, pp := range prefixes {
			full := joinPrefix(pp, p)
			if !strings.HasPrefix(full, "/") {
				continue
			}
			for _, mt := range methods {
				out = append(out, route{
					method: mt, path: full, handler: handler,
					prefix: pp, start: start, end: end, registered: reg,
				})
			}
		}
	}

	return out
}

// pyHandlerAfter finds the `def` a decorator on line reg (1-based) applies to: the next
// def line reached over only decorators, blank lines and the rest of the decorator's own
// argument list. defLine is 1-based, 0 when there is none.
func pyHandlerAfter(lines []string, reg int) (name string, defLine int) {
	for i := reg; i < len(lines) && i < reg+30; i++ {
		if m := pyDefLine.FindStringSubmatch(lines[i]); m != nil {
			return m[2], i + 1
		}
		t := strings.TrimSpace(lines[i])
		if t == "" || strings.HasPrefix(t, "@") || strings.HasPrefix(t, ")") || strings.HasSuffix(t, ",") ||
			strings.Contains(t, "=") || strings.HasPrefix(t, `"`) || strings.HasPrefix(t, "'") {
			continue
		}

		return "", 0
	}

	return "", 0
}

// pyBlockEnd is the last non-blank line of the block whose header is on defLine (1-based):
// every following line indented deeper than the header belongs to it, and a signature's
// closing `)` at the header's indent is still the header.
func pyBlockEnd(lines []string, defLine int) int {
	header := lines[defLine-1]
	indent := len(header) - len(strings.TrimLeft(header, " \t"))
	end := defLine
	for i := defLine; i < len(lines); i++ {
		l := lines[i]
		if strings.TrimSpace(l) == "" {
			continue
		}
		if len(l)-len(strings.TrimLeft(l, " \t")) <= indent && !strings.HasPrefix(strings.TrimSpace(l), ")") {
			break
		}
		end = i + 1
	}

	return end
}

// ---- Java / Kotlin (Spring) -------------------------------------------------------------

func extractJavaRoutes(src string) []route {
	lines := newLineIndex(src)
	type classRange struct {
		start, end int
		prefix     string
		anno       int
	}
	var classes []classRange
	for _, m := range javaClassMapping.FindAllStringSubmatchIndex(src, -1) {
		open := m[1] - 1
		if end := matchBracket(src, open); end > 0 {
			classes = append(classes, classRange{start: open, end: end, prefix: src[m[2]:m[3]], anno: m[0]})
		}
	}

	var out []route
	for _, m := range javaRouteAnno.FindAllStringSubmatchIndex(src, -1) {
		kind, p := src[m[2]:m[3]], src[m[4]:m[5]]
		isClassLevel := false
		prefix := ""
		for _, c := range classes {
			if c.anno == m[0] {
				isClassLevel = true

				break
			}
			if m[0] > c.start && m[0] < c.end {
				prefix = c.prefix // the innermost class wins: later ranges are nested
			}
		}
		if isClassLevel {
			// The class-level @RequestMapping prefixes its methods; it is not a route.
			continue
		}
		if prefix == "" && !strings.HasPrefix(p, "/") {
			continue
		}
		reg := lines.line(m[0])
		start, end, handler := reg, reg, ""
		// The annotation's own closing paren, then the method it decorates.
		annoClose := matchBracket(src, m[0]+strings.Index(src[m[0]:], "("))
		if annoClose > 0 {
			if nm := javaMethodName.FindStringSubmatchIndex(src[annoClose+1:]); nm != nil {
				handler = src[annoClose+1+nm[2] : annoClose+1+nm[3]]
				if pc := matchBracket(src, annoClose+nm[1]); pc > 0 {
					if body := strings.IndexAny(src[pc:], "{;="); body >= 0 && src[pc+body] == '{' {
						if be := matchBracket(src, pc+body); be > 0 {
							end = lines.line(be)
						}
					}
				}
			}
		}
		out = append(out, route{
			method: strings.ToUpper(kind), path: joinPrefix(prefix, p), handler: handler,
			prefix: prefix, start: start, end: end, registered: reg,
		})
	}

	return out
}

// routeSite is one route found in one file, before it becomes a node.
type routeSite struct {
	key      string
	file     string
	language string
	route    route
}

// addRouteSites turns the routes of a scan into edges and nodes.
//
// A route key served from several files is several nodes, one per file: the same
// `GET /v1/users` registered in two packages (a v1 and a v2 handler, a route and its
// mock, a monolith and its extracted service) are different places to look at, and one
// finding can sit in either. Within one file the first registration of a key stands.
//
// The ids are stable whatever order the files were walked in: the file that sorts first
// keeps the plain `route:<key>` id (what the server has always been sent for a unique
// key), and the others are `route:<key>@<path>`.
func addRouteSites(sites []routeSite, add func(CrossRepoEdge, Node)) {
	byKey := map[string][]routeSite{}
	for _, s := range sites {
		byKey[s.key] = append(byKey[s.key], s)
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		group := byKey[key]
		sort.SliceStable(group, func(i, j int) bool {
			if group[i].file != group[j].file {
				return group[i].file < group[j].file
			}

			return group[i].route.registered < group[j].route.registered
		})
		seenFile := map[string]bool{}
		first := true
		for _, s := range group {
			if seenFile[s.file] {
				continue
			}
			seenFile[s.file] = true

			id, edgeID := "route:"+key, "xr-provides-"+safeID(key)
			if !first {
				id += "@" + s.file
				edgeID += "-" + safeID(s.file) + "-" + shortHash(s.file)
			}
			first = false

			props := map[string]any{"method": s.route.method, "registeredLine": s.route.registered}
			if s.route.handler != "" {
				props["handler"] = s.route.handler
			}
			if s.route.prefix != "" {
				props["mountPrefix"] = s.route.prefix
			}
			add(CrossRepoEdge{
				ID:          edgeID,
				LocalNodeID: id,
				JoinKind:    "http_route",
				JoinKey:     key,
				Role:        "provides",
				Confidence:  0.8, // a route matched by pattern, not by understanding the framework
				Properties:  map[string]any{"path": s.file},
			}, Node{
				ID: id, Kind: "route", Name: key, Path: s.file, Language: s.language,
				StartLine: s.route.start, EndLine: s.route.end, Exported: true, Properties: props,
			})
		}
	}
}

func shortHash(s string) string {
	sum := sha1.Sum([]byte(s))

	return hex.EncodeToString(sum[:4])
}
