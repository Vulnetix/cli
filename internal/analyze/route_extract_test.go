package analyze

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// brief is the part of a route a golden case compares.
type brief struct {
	Method, Path, Handler string
	Start, End            int
}

func briefs(rs []route) []brief {
	out := make([]brief, 0, len(rs))
	for _, r := range rs {
		out = append(out, brief{Method: r.method, Path: r.path, Handler: r.handler, Start: r.start, End: r.end})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}

		return out[i].Method < out[j].Method
	})

	return out
}

func TestStripComments_KeepsLineNumbers(t *testing.T) {
	src := "a\n/* one\ntwo\nthree */\nb // tail\nc"
	out := stripComments(src, "go")
	require.Equal(t, 6, len(splitLines(out)), "the stripped text has the same number of lines as the source")
	require.Equal(t, "b ", splitLines(out)[4])
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == '\n' {
			out = append(out, cur)
			cur = ""

			continue
		}
		cur += string(c)
	}

	return append(out, cur)
}

// Every route carries the line it sits on and the handler token, so a finding inside the
// handler can be tied to it.
func TestExtractRoutes_GoLinesAndHandlers(t *testing.T) {
	src := `package main

import "github.com/go-chi/chi/v5"

func main() {
	r := chi.NewRouter()
	r.Get("/v1/users", h.ListUsers)
	r.Post("/v1/users", func(w http.ResponseWriter, req *http.Request) {
		save(req)
		reply(w)
	})
	r.With(auth).Delete("/v1/users/{id}", removeUser)
}

func removeUser(w http.ResponseWriter, r *http.Request) {
	log()
	doIt()
}
`
	got := briefs(extractRoutes(src, "go"))
	require.Equal(t, []brief{
		{"GET", "/v1/users", "h.ListUsers", 7, 7},
		{"POST", "/v1/users", "", 8, 11},
		{"DELETE", "/v1/users/{id}", "removeUser", 15, 18}, // the declaration, not the registration
	}, got)
}

func TestExtractRoutes_GoUppercaseVerbsAndGroups(t *testing.T) {
	src := `package main

func routes() {
	r := gin.Default()
	api := r.Group("/api")
	v1 := api.Group("/v1")
	v1.GET("/users", listUsers)
	v1.POST("/users", createUser)
	r.GET("/top", top)
}
`
	require.Equal(t, []brief{
		{"GET", "/api/v1/users", "listUsers", 7, 7},
		{"POST", "/api/v1/users", "createUser", 8, 8},
		{"GET", "/top", "top", 9, 9},
	}, briefs(extractRoutes(src, "go")))
}

func TestExtractRoutes_GoChiRouteMountAndNoFalsePrefix(t *testing.T) {
	src := `package main

func routes() {
	r := chi.NewRouter()
	r.Route("/api", func(r chi.Router) {
		r.Get("/health-ish", a)
		r.Route("/v2", func(r chi.Router) {
			r.Get("/things", b)
		})
	})
	r.Get("/outside", c)
	r.Mount("/admin", adminRouter())
}

func adminRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/users", d)
	return r
}

func other() {
	r := chi.NewRouter()
	r.Get("/unrelated", e)
}
`
	require.Equal(t, []brief{
		{"GET", "/admin/users", "d", 17, 17},
		{"GET", "/api/health-ish", "a", 6, 6},
		{"GET", "/api/v2/things", "b", 8, 8},
		{"GET", "/outside", "c", 11, 11},
		{"GET", "/unrelated", "e", 23, 23},
	}, briefs(extractRoutes(src, "go")), "a router mounted elsewhere in the file carries its prefix; one that is not mounted carries none")
}

func TestExtractRoutes_GoVariableInAnotherFunctionIsNotTheGroup(t *testing.T) {
	src := `package main

func a(r *gin.Engine) {
	api := r.Group("/api")
	api.GET("/inside", h1)
}

func b(api *gin.RouterGroup) {
	api.GET("/param", h2)
}
`
	require.Equal(t, []brief{
		{"GET", "/api/inside", "h1", 5, 5},
		{"GET", "/param", "h2", 9, 9},
	}, briefs(extractRoutes(src, "go")), "b's api is a parameter; a's group must not leak into it")
}

func TestExtractRoutes_GoGorillaSubrouter(t *testing.T) {
	src := `package main

func routes() {
	r := mux.NewRouter()
	s := r.PathPrefix("/products").Subrouter()
	s.HandleFunc("/list", listProducts)
}
`
	require.Equal(t, []brief{{"HANDLEFUNC", "/products/list", "listProducts", 6, 6}}, briefs(extractRoutes(src, "go")))
}

func TestExtractRoutes_ExpressMountPrefixes(t *testing.T) {
	src := `const express = require('express');
const app = express();
const apiRouter = express.Router();
const usersRouter = express.Router();

apiRouter.use('/users', usersRouter);
app.use('/api', apiRouter);

usersRouter.get('/:id', getUser);
usersRouter.post('/', async (req, res) => {
  await save(req);
  res.send('ok');
});
app.get('/ping2', (req, res) => res.send('x'));
apiRouter.get('/status2', statusHandler);

function getUser(req, res) {
  res.json({});
}
`
	got := briefs(extractRoutes(src, "javascript"))
	require.Equal(t, []brief{
		{"GET", "/api/status2", "statusHandler", 15, 15},
		{"POST", "/api/users/", "", 10, 13},
		{"GET", "/api/users/:id", "getUser", 17, 19},
		{"GET", "/ping2", "", 14, 14},
	}, got)
}

func TestExtractRoutes_ExpressNoMountMeansNoPrefix(t *testing.T) {
	src := `const router = express.Router();
router.get('/items', listItems);
module.exports = router;
`
	require.Equal(t, []brief{{"GET", "/items", "listItems", 2, 2}}, briefs(extractRoutes(src, "javascript")),
		"the router is mounted in another file: guessing a prefix would invent an endpoint")
}

func TestExtractRoutes_ExpressMountedTwiceIsServedTwice(t *testing.T) {
	src := `const r = express.Router();
app.use('/v1', r);
app.use('/v2', r);
r.get('/x', h);
`
	got := briefs(extractRoutes(src, "javascript"))
	require.Equal(t, []brief{{"GET", "/v1/x", "h", 4, 4}, {"GET", "/v2/x", "h", 4, 4}}, got)
}

func TestExtractRoutes_KoaPrefixOption(t *testing.T) {
	src := `const Router = require('koa-router');
const router = new Router({ prefix: '/api' });
router.get('/things', listThings);
`
	require.Equal(t, []brief{{"GET", "/api/things", "listThings", 3, 3}}, briefs(extractRoutes(src, "javascript")))
}

func TestExtractRoutes_FastAPIPrefixes(t *testing.T) {
	src := `from fastapi import FastAPI, APIRouter

app = FastAPI()
router = APIRouter(prefix="/users")
admin = APIRouter()

@router.get("/{id}")
async def read_user(id: int):
    user = load(id)
    return user

@router.post("")
def create_user():
    return {}

@admin.get("/stats")
def stats():
    return 1

app.include_router(router, prefix="/api")
app.include_router(admin, prefix="/admin")
`
	require.Equal(t, []brief{
		{"GET", "/admin/stats", "stats", 16, 18},
		{"POST", "/api/users", "create_user", 12, 14},
		{"GET", "/api/users/{id}", "read_user", 7, 10},
	}, briefs(extractRoutes(src, "python")))
}

func TestExtractRoutes_FlaskBlueprintPrefixes(t *testing.T) {
	src := `bp = Blueprint("bp", __name__, url_prefix="/own")
plain = Blueprint("plain", __name__)
unmounted = Blueprint("u", __name__, url_prefix="/u")

@bp.route("/a", methods=["POST", "PUT"])
def a():
    pass

@plain.route("/p")
def p():
    pass

@unmounted.get("/z")
def z():
    pass

app.register_blueprint(bp, url_prefix="/over")
app.register_blueprint(plain)
`
	got := briefs(extractRoutes(src, "python"))
	var paths []string
	for _, g := range got {
		paths = append(paths, g.Method+" "+g.Path)
	}
	require.ElementsMatch(t, []string{"POST /over/a", "PUT /over/a", "ROUTE /p", "GET /u/z"}, paths,
		"a registration's url_prefix replaces the blueprint's own; an unmounted blueprint keeps its own prefix")
}

func TestExtractRoutes_SpringClassPrefix(t *testing.T) {
	src := `package demo;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/{id}")
    public User get(@PathVariable Long id) {
        return svc.find(id);
    }

    @PostMapping(value = "")
    public User create(@RequestBody User u) { return svc.save(u); }
}

@RestController
class Other {
    @GetMapping("/plain")
    String plain() { return "x"; }
}
`
	got := briefs(extractRoutes(src, "java"))
	require.Equal(t, []brief{
		{"GET", "/api/users/{id}", "get", 7, 10},
		{"GET", "/plain", "plain", 18, 19},
	}, got, "the class-level @RequestMapping is a prefix, not a route; an empty method path is skipped")
}

// A route key served from two files is two nodes, and the plain id stays on the file that
// sorts first however the walk ordered them.
func TestAddRouteSites_DuplicateKeysAreSeparateNodesPerFile(t *testing.T) {
	r1 := route{method: "GET", path: "/v1/users", handler: "a", start: 10, end: 12, registered: 10}
	r2 := route{method: "GET", path: "/v1/users", handler: "b", start: 3, end: 3, registered: 3}
	r3 := route{method: "GET", path: "/v1/users", handler: "dup", start: 20, end: 20, registered: 20}
	for _, order := range [][]routeSite{
		{{key: "GET /v1/users", file: "svc/b.go", language: "go", route: r2}, {key: "GET /v1/users", file: "api/a.go", language: "go", route: r1}},
		{{key: "GET /v1/users", file: "api/a.go", language: "go", route: r1}, {key: "GET /v1/users", file: "svc/b.go", language: "go", route: r2}},
	} {
		var edges []CrossRepoEdge
		var nodes []Node
		seen := map[string]bool{}
		addRouteSites(append(order, routeSite{key: "GET /v1/users", file: "api/a.go", language: "go", route: r3}), func(e CrossRepoEdge, n Node) {
			if seen[e.ID] {
				return
			}
			seen[e.ID] = true
			edges, nodes = append(edges, e), append(nodes, n)
		})
		require.Len(t, nodes, 2, "one node per file, the second registration in a.go is merged")
		require.Len(t, edges, 2)
		byID := map[string]Node{}
		for _, n := range nodes {
			byID[n.ID] = n
		}
		plain, ok := byID["route:GET /v1/users"]
		require.True(t, ok)
		require.Equal(t, "api/a.go", plain.Path)
		require.Equal(t, 10, plain.StartLine)
		require.Equal(t, 12, plain.EndLine)
		require.Equal(t, "a", plain.Properties["handler"])
		other, ok := byID["route:GET /v1/users@svc/b.go"]
		require.True(t, ok)
		require.Equal(t, 3, other.StartLine)
		require.Equal(t, "go", other.Language)
		for _, e := range edges {
			require.Equal(t, "GET /v1/users", e.JoinKey)
			require.Equal(t, "http_route", e.JoinKind)
		}
		require.NotEqual(t, edges[0].ID, edges[1].ID)
	}
}

// End to end through the collector: lines and handler reach the node.
func TestCollectContracts_RouteNodeCarriesLinesAndHandler(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "api"), 0o755))
	src := `package api

import "github.com/go-chi/chi/v5"

/* a block
   comment */
func Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/v1/widgets", listWidgets)
	return r
}
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "api", "routes.go"), []byte(src), 0o644))
	files := &fileStats{files: []*FileRecord{{Path: "api/routes.go", Language: "go"}}}
	b := NewBuilder(Tool{Name: "test", Version: "dev"}, Target{RepoID: "acme/demo", RootPath: dir}, time.Now())
	st := collectContracts(b, dir, files, nil, Target{RepoID: "acme/demo"})
	var found *Node
	for i := range st.nodes {
		if st.nodes[i].Kind == "route" {
			found = &st.nodes[i]
		}
	}
	require.NotNil(t, found)
	require.Equal(t, "GET /v1/widgets", found.Name)
	require.Equal(t, 9, found.StartLine, "the line in the file, after a block comment")
	require.Equal(t, "listWidgets", found.Properties["handler"])
}
