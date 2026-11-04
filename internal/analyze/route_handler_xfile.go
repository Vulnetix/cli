package analyze

// Go handlers declared in another file.
//
// A Go service registers its routes in one place (main.go: r.Get("/x", handler.List(deps)))
// and writes the handlers elsewhere (internal/handler/list.go). The route's file is then the
// registration file, where no finding about the handler ever sits, so a SAST finding in the
// handler could never be tied to its route. This resolves the handler named at the
// registration to its declaration in the repository and records that file and the body's
// lines on the route, only when the declaration is unambiguous:
//
//   - pkg.Func: a function Func declared in a directory whose name is pkg (the package's
//     import name, as Go spells it at the call), exactly one;
//   - x.Method: otherwise a method named Method, exactly one in the repository;
//   - Func: a function Func in the route file's own directory (the same package), exactly one.
//
// Anything else stays unresolved. A wrong handler file would tie findings to a route they
// have nothing to do with; a missing one only leaves the finding unplaced.

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

type goDecl struct {
	file, dir  string
	method     bool
	start, end int
}

// goDeclIndex maps a function or method name to its declarations.
type goDeclIndex map[string][]goDecl

// buildGoDeclIndex reads the declarations of the repository's non-test Go files.
func buildGoDeclIndex(root string, files []string) goDeclIndex {
	idx := goDeclIndex{}
	for _, rel := range files {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue
		}
		src := stripComments(string(body), "go")
		lines := newLineIndex(src)
		dir := path.Dir(filepath.ToSlash(rel))
		for _, m := range goFuncDecl.FindAllStringSubmatchIndex(src, -1) {
			bodyOpen := goBodyOpen(src, m[1]-1)
			if bodyOpen < 0 {
				continue
			}
			closeIdx := scanBlock(src, bodyOpen, "go")
			if closeIdx < 0 {
				continue
			}
			name := src[m[2]:m[3]]
			idx[name] = append(idx[name], goDecl{
				file: filepath.ToSlash(rel), dir: dir, method: strings.Contains(src[m[0]:m[2]], "("),
				start: lines.line(m[0]), end: lines.line(closeIdx),
			})
		}
	}

	return idx
}

// resolve finds the one declaration a handler token names, for a route in routeFile.
func (idx goDeclIndex) resolve(token, routeFile string) (goDecl, bool) {
	token = strings.TrimSpace(token)
	if i := strings.IndexByte(token, '('); i >= 0 {
		token = token[:i] // handler.List(deps): the factory that builds the handler
	}
	if token == "" || strings.ContainsAny(token, " \t{}") {
		return goDecl{}, false
	}
	parts := strings.Split(token, ".")
	name := parts[len(parts)-1]
	decls := idx[name]
	pick := func(keep func(goDecl) bool) (goDecl, bool) {
		var hit goDecl
		n := 0
		for _, d := range decls {
			if keep(d) {
				hit = d
				n++
			}
		}

		return hit, n == 1
	}
	if len(parts) == 1 {
		dir := path.Dir(filepath.ToSlash(routeFile))

		return pick(func(d goDecl) bool { return !d.method && d.dir == dir })
	}
	qual := parts[len(parts)-2]
	if d, ok := pick(func(d goDecl) bool { return !d.method && path.Base(d.dir) == qual }); ok {
		return d, true
	}

	return pick(func(d goDecl) bool { return d.method })
}

// resolveGoHandlers fills handlerFile and the handler's lines on Go routes whose handler
// was not found in their own file.
func resolveGoHandlers(root string, goFiles []string, sites []routeSite) {
	need := false
	for _, s := range sites {
		if s.language == "go" && s.route.handler != "" && s.route.hStart == 0 {
			need = true

			break
		}
	}
	if !need {
		return
	}
	idx := buildGoDeclIndex(root, goFiles)
	for i := range sites {
		s := &sites[i]
		if s.language != "go" || s.route.handler == "" || s.route.hStart != 0 {
			continue
		}
		if d, ok := idx.resolve(s.route.handler, s.file); ok && d.file != s.file {
			s.route.handlerFile, s.route.hStart, s.route.hEnd = d.file, d.start, d.end
		}
	}
}
