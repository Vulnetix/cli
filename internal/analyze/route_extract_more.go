package analyze

// Route extraction for the frameworks route_extract.go does not read: NestJS decorators,
// Django urlpatterns, aiohttp, Ktor routing and Rails/Sinatra. The same rules hold: a
// prefix is applied only when it is visible in the file, a route whose prefix cannot be
// seen keeps its relative path (or is dropped when it has none), and a handler range is
// given only when its extent is read, never guessed.

import (
	"regexp"
	"strings"
)

var (
	// NestJS: @Controller('users') on the class, @Get(':id') on its methods.
	nestController = regexp.MustCompile(`@Controller\(\s*(?:['"` + "`" + `]([^'"` + "`" + `]*)['"` + "`" + `])?[^)]*\)`)
	nestMethod     = regexp.MustCompile(`@(Get|Post|Put|Patch|Delete|All|Head|Options)\(\s*(?:['"` + "`" + `]([^'"` + "`" + `]*)['"` + "`" + `])?\s*\)`)

	// Django: path('users/<int:pk>/', view) in a urlpatterns list. re_path is a regex and
	// is not read; include() is another file's routes.
	djangoPath   = regexp.MustCompile(`\bpath\(\s*['"]([^'"]*)['"]\s*,\s*([A-Za-z_][\w.]*)`)
	djangoConv   = regexp.MustCompile(`<(?:[a-z_]+:)?([A-Za-z_]\w*)>`)
	djangoMarker = regexp.MustCompile(`\burlpatterns\s*(?:\+?=)`)

	// aiohttp: web.get('/x', h), app.router.add_get('/x', h), add_route('GET', '/x', h).
	// router.get is FastAPI's decorator; aiohttp's router methods are always add_*.
	aioCall  = regexp.MustCompile(`(?:\bweb\.|\.add_)(get|post|put|patch|delete|head|options|view)\(\s*['"]([^'"]+)['"]`)
	aioRoute = regexp.MustCompile(`\.add_route\(\s*['"]([A-Za-z*]+)['"]\s*,\s*['"]([^'"]+)['"]`)

	// Ktor: route("/api") { get("/x") { ... } }, and get { } with no path inside a route.
	ktorRoute = regexp.MustCompile(`\broute\(\s*"([^"]*)"\s*\)\s*\{`)
	ktorVerb  = regexp.MustCompile(`\b(get|post|put|patch|delete|head|options)\s*(?:\(\s*(?:"([^"]*)")?\s*\))?\s*\{`)

	// Rails routes.rb and Sinatra: get '/x', post "x", match ..., via:, resources :users.
	rbVerb      = regexp.MustCompile(`^\s*(get|post|put|patch|delete|head|options)\s*\(?\s*['"]([^'"]+)['"]`)
	rbResources = regexp.MustCompile(`^\s*(resources|resource)\s*\(?\s*:([a-z_]\w*)([^\n]*)`)
	rbNamespace = regexp.MustCompile(`^\s*namespace\s*\(?\s*:([a-z_]\w*)[^\n]*\bdo\b`)
	rbScope     = regexp.MustCompile(`^\s*scope\s*\(?\s*(?:path:\s*)?['"]([^'"]*)['"][^\n]*\bdo\b`)
	rbOnly      = regexp.MustCompile(`only:\s*\[([^\]]*)\]|only:\s*:(\w+)`)
	rbExcept    = regexp.MustCompile(`except:\s*\[([^\]]*)\]|except:\s*:(\w+)`)
	rbDoEnd     = regexp.MustCompile(`\bdo\b(\s*\|[^|]*\|)?\s*$`)
	rbEnd       = regexp.MustCompile(`^\s*end\b`)
	// Keywords that open a block closed by `end` without a `do` (a def or an if in a
	// Sinatra app), so its `end` does not close a namespace.
	rbOpener = regexp.MustCompile(`^\s*(def|if|unless|class|module|case|while|until|begin)\b`)
	rbTo     = regexp.MustCompile(`(?:to:|=>)\s*['"]([^'"]+)['"]`)
)

// extractNestRoutes reads NestJS controllers: each method decorator under a @Controller
// takes the controller's path as its prefix.
func extractNestRoutes(src string) []route {
	lines := newLineIndex(src)
	type ctrl struct {
		at     int
		prefix string
	}
	var ctrls []ctrl
	for _, m := range nestController.FindAllStringSubmatchIndex(src, -1) {
		p := ""
		if m[2] >= 0 {
			p = strings.Trim(src[m[2]:m[3]], "/")
		}
		if p != "" {
			p = "/" + p
		}
		ctrls = append(ctrls, ctrl{at: m[0], prefix: p})
	}
	if len(ctrls) == 0 {
		return nil
	}
	var out []route
	for _, m := range nestMethod.FindAllStringSubmatchIndex(src, -1) {
		prefix := ""
		seen := false
		for _, c := range ctrls {
			if c.at < m[0] {
				prefix, seen = c.prefix, true
			}
		}
		if !seen {
			continue
		}
		p := ""
		if m[4] >= 0 {
			p = src[m[4]:m[5]]
		}
		method := strings.ToUpper(src[m[2]:m[3]])
		if method == "ALL" {
			method = "ANY"
		}
		reg := lines.line(m[0])
		full := joinPrefix(prefix, p)
		if !strings.HasPrefix(full, "/") {
			full = "/" + full
		}
		out = append(out, route{method: method, path: full, prefix: prefix, start: reg, end: reg, registered: reg})
	}

	return out
}

// extractDjangoRoutes reads path() entries in a file that declares urlpatterns. Their
// paths are relative to wherever the project includes the file, which is not visible
// here, so they are rooted at "/" as written.
func extractDjangoRoutes(src string) []route {
	if !djangoMarker.MatchString(src) {
		return nil
	}
	lines := newLineIndex(src)
	var out []route
	for _, m := range djangoPath.FindAllStringSubmatchIndex(src, -1) {
		view := src[m[4]:m[5]]
		if view == "include" {
			continue
		}
		p := djangoConv.ReplaceAllString(src[m[2]:m[3]], "{$1}")
		reg := lines.line(m[0])
		out = append(out, route{method: "ANY", path: "/" + strings.TrimPrefix(p, "/"), handler: view, start: reg, end: reg, registered: reg})
	}

	return out
}

// extractAiohttpRoutes reads aiohttp registrations. Decorated routes (@routes.get) are
// already read by the FastAPI/Flask decorator pattern.
func extractAiohttpRoutes(src string) []route {
	lines := newLineIndex(src)
	var out []route
	for _, m := range aioCall.FindAllStringSubmatchIndex(src, -1) {
		method := strings.ToUpper(src[m[2]:m[3]])
		if method == "VIEW" {
			method = "ANY"
		}
		reg := lines.line(m[0])
		out = append(out, route{method: method, path: src[m[4]:m[5]], start: reg, end: reg, registered: reg})
	}
	for _, m := range aioRoute.FindAllStringSubmatchIndex(src, -1) {
		method := strings.ToUpper(src[m[2]:m[3]])
		if method == "*" {
			method = "ANY"
		}
		reg := lines.line(m[0])
		out = append(out, route{method: method, path: src[m[4]:m[5]], start: reg, end: reg, registered: reg})
	}

	return out
}

// extractKtorRoutes reads Ktor's routing DSL. A verb takes every enclosing route("…")
// block as its prefix; its own block is the handler.
func extractKtorRoutes(src string) []route {
	if !strings.Contains(src, "routing") && !strings.Contains(src, "fun Route.") {
		return nil
	}
	lines := newLineIndex(src)
	type block struct {
		start, end int
		prefix     string
	}
	var blocks []block
	for _, m := range ktorRoute.FindAllStringSubmatchIndex(src, -1) {
		if end := matchBracket(src, m[1]-1); end > 0 {
			blocks = append(blocks, block{start: m[1] - 1, end: end, prefix: src[m[2]:m[3]]})
		}
	}
	var out []route
	for _, m := range ktorVerb.FindAllStringSubmatchIndex(src, -1) {
		// "get(" as a method call on something (map.get(...)) is not a route.
		if m[0] > 0 && src[m[0]-1] == '.' {
			continue
		}
		prefix := ""
		for _, b := range blocks { // outer blocks come first, so this joins outer to inner
			if m[0] > b.start && m[0] < b.end {
				prefix = joinPrefix(prefix, b.prefix)
			}
		}
		p := ""
		if m[4] >= 0 {
			p = src[m[4]:m[5]]
		}
		if prefix == "" && !strings.HasPrefix(p, "/") {
			continue
		}
		reg := lines.line(m[0])
		r := route{method: strings.ToUpper(src[m[2]:m[3]]), path: joinPrefix(prefix, p), prefix: prefix, start: reg, end: reg, registered: reg}
		if end := matchBracket(src, m[1]-1); end > 0 {
			r.end = lines.line(end)
			r.hStart, r.hEnd = reg, r.end
		}
		out = append(out, r)
	}

	return out
}

// railsActions are the routes `resources` declares, in the order Rails lists them.
var railsActions = []struct {
	action, method, suffix string
	member                 bool
}{
	{"index", "GET", "", false}, {"create", "POST", "", false}, {"new", "GET", "/new", false},
	{"show", "GET", "", true}, {"update", "PATCH", "", true}, {"update", "PUT", "", true},
	{"destroy", "DELETE", "", true}, {"edit", "GET", "/edit", true},
}

// extractRubyRoutes reads Rails routes.rb and Sinatra: verbs, resources and resource
// (with only:/except:), and namespace/scope/nested-resources blocks as prefixes. Blocks
// are tracked by their do … end, line by line.
func extractRubyRoutes(src string) []route {
	type frame struct {
		prefix string
		push   bool // whether this do-block carries a prefix (else it is some other block)
	}
	var stack []frame
	prefix := func() string {
		p := ""
		for _, f := range stack {
			if f.push {
				p = joinPrefix(p, f.prefix)
			}
		}

		return p
	}
	var out []route
	for i, line := range strings.Split(src, "\n") {
		n := i + 1
		opens := rbDoEnd.MatchString(line)
		switch {
		case rbEnd.MatchString(line):
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}

			continue
		case rbNamespace.MatchString(line):
			stack = append(stack, frame{prefix: "/" + rbNamespace.FindStringSubmatch(line)[1], push: true})

			continue
		case rbScope.MatchString(line):
			stack = append(stack, frame{prefix: "/" + strings.Trim(rbScope.FindStringSubmatch(line)[1], "/"), push: true})

			continue
		}
		if m := rbResources.FindStringSubmatch(line); m != nil {
			singular := m[1] == "resource"
			base := joinPrefix(prefix(), "/"+m[2])
			keep := railsKeep(m[3])
			for _, a := range railsActions {
				if !keep(a.action) {
					continue
				}
				p := base
				if a.member && !singular {
					p += "/{id}"
				}
				if singular && a.action == "index" {
					continue // a singular resource has no index
				}
				out = append(out, route{method: a.method, path: p + a.suffix, handler: m[2] + "#" + a.action, prefix: prefix(), start: n, end: n, registered: n})
			}
			if opens {
				nested := "/" + m[2]
				if !singular {
					nested += "/{" + strings.TrimSuffix(m[2], "s") + "_id}"
				}
				stack = append(stack, frame{prefix: nested, push: true})
			}

			continue
		}
		if m := rbVerb.FindStringSubmatch(line); m != nil {
			p := m[2]
			pre := prefix()
			if pre == "" && !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			r := route{method: strings.ToUpper(m[1]), path: joinPrefix(pre, p), prefix: pre, start: n, end: n, registered: n}
			if to := rbTo.FindStringSubmatch(line); to != nil {
				r.handler = to[1]
			}
			out = append(out, r)
		}
		if opens || rbOpener.MatchString(line) {
			stack = append(stack, frame{})
		}
	}

	return out
}

// railsKeep reads only:/except: on a resources line.
func railsKeep(opts string) func(string) bool {
	list := func(m []string) map[string]bool {
		set := map[string]bool{}
		raw := m[1]
		if raw == "" {
			raw = m[2]
		}
		for _, s := range strings.Split(raw, ",") {
			s = strings.Trim(strings.TrimSpace(s), ":'\"")
			if s != "" {
				set[s] = true
			}
		}

		return set
	}
	if m := rbOnly.FindStringSubmatch(opts); m != nil {
		only := list(m)

		return func(a string) bool { return only[a] }
	}
	if m := rbExcept.FindStringSubmatch(opts); m != nil {
		except := list(m)

		return func(a string) bool { return !except[a] }
	}

	return func(string) bool { return true }
}
