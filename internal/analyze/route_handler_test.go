package analyze

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// hrange is the handler body range a route carries, 0 0 when it carries none.
type hrange struct {
	Route      string
	Start, End int
}

func handlerRanges(rs []route) []hrange {
	out := make([]hrange, 0, len(rs))
	for _, r := range rs {
		out = append(out, hrange{Route: r.method + " " + r.path, Start: r.hStart, End: r.hEnd})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Route < out[j].Route })

	return out
}

// ---- Go ---------------------------------------------------------------------------------

func TestHandlerRange_GoInline(t *testing.T) {
	src := `package main

func main() {
	r := chi.NewRouter()
	r.Get("/a", func(w http.ResponseWriter, req *http.Request) {
		save(req)
		reply(w)
	})
	g.GET("/b", func(c *gin.Context) {
		c.JSON(200, nil)
	})
	e.POST("/c", auth, func(c echo.Context) error {
		return c.NoContent(204)
	})
	mux.Handle("/d", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	r.Get("/e", func(w http.ResponseWriter, r *http.Request) { reply(w) })
}
`
	require.Equal(t, []hrange{
		{"GET /a", 5, 8},
		{"GET /b", 9, 11},
		{"GET /e", 18, 18},
		{"HANDLE /d", 15, 17},
		{"POST /c", 12, 14},
	}, handlerRanges(extractRoutes(src, "go")))
}

func TestHandlerRange_GoNamed(t *testing.T) {
	src := `package main

func routes() {
	r.Get("/a", listUsers)
	r.Get("/b", h.Show)
	r.Get("/c", other.Elsewhere)
	r.Get("/d", missing)
}

func listUsers(w http.ResponseWriter, r *http.Request) {
	log()
	for _, u := range users {
		emit(u)
	}
}

func (h *Handler) Show(w http.ResponseWriter, r *http.Request) {
	h.render(w)
}

// Elsewhere is a function here, but other.Elsewhere is not it.
func Elsewhere(w http.ResponseWriter, r *http.Request) {
	x()
}
`
	require.Equal(t, []hrange{
		{"GET /a", 10, 15},
		{"GET /b", 17, 19},
		{"GET /c", 0, 0}, // a selector on another package is never matched to a function here
		{"GET /d", 0, 0}, // no declaration in this file
	}, handlerRanges(extractRoutes(src, "go")))
}

func TestHandlerRange_GoAmbiguousNameGivesNoRange(t *testing.T) {
	src := `package main

func routes() {
	r.Get("/a", h.Show)
}

func (a *A) Show(w http.ResponseWriter, r *http.Request) {
	x()
}

func (b *B) Show(w http.ResponseWriter, r *http.Request) {
	y()
}
`
	require.Equal(t, []hrange{{"GET /a", 0, 0}}, handlerRanges(extractRoutes(src, "go")))
}

func TestHandlerRange_GoBracesInStringsRunesAndComments(t *testing.T) {
	src := "package main\n\n" +
		"func main() {\n" +
		"\tr.Get(\"/a\", func(w http.ResponseWriter, r *http.Request) {\n" +
		"\t\ts := \"}}}\"\n" +
		"\t\tc := '}'\n" +
		"\t\tq := '\\''\n" +
		"\t\traw := `{{{`\n" +
		"\t\t// } closes nothing\n" +
		"\t\t/* }\n" +
		"\t\t} */\n" +
		"\t\tdo(s, c, q, raw)\n" +
		"\t})\n" +
		"\tr.Get(\"/b\", func(w http.ResponseWriter, r *http.Request) {\n" +
		"\t\tother()\n" +
		"\t})\n" +
		"}\n"
	want := []hrange{{"GET /a", 4, 13}, {"GET /b", 14, 16}}
	require.Equal(t, want, handlerRanges(extractRoutes(src, "go")), "raw source")
	require.Equal(t, want, handlerRanges(extractRoutes(stripComments(src, "go"), "go")), "after stripComments")
}

func TestHandlerRange_GoNestedFunctionsStayInside(t *testing.T) {
	src := `package main

func main() {
	r.Get("/a", func(w http.ResponseWriter, r *http.Request) {
		go func() {
			if ok {
				work()
			}
		}()
		cb := func() int { return 1 }
		_ = cb
	})
	r.Get("/b", func(w http.ResponseWriter, r *http.Request) {
		z()
	})
}
`
	require.Equal(t, []hrange{{"GET /a", 4, 12}, {"GET /b", 13, 15}}, handlerRanges(extractRoutes(src, "go")))
}

func TestHandlerRange_GoUnbalancedBracesGiveNoRange(t *testing.T) {
	// The call closes but the body does not.
	body := `package main

func main() {
	r.Get("/a", func(w http.ResponseWriter, r *http.Request) {
		if x {
			y()
	})
}
`
	for name, src := range map[string]string{
		"body never closes": body,
		"call never closes": "package main\n\nfunc main() {\n\tr.Get(\"/a\", func(w http.ResponseWriter, r *http.Request) {\n\t\tz()\n",
		"named never closes": `package main

func main() {
	r.Get("/a", named)
}

func named(w http.ResponseWriter, r *http.Request) {
	if x {
		y()
`,
	} {
		for _, hr := range handlerRanges(extractRoutes(src, "go")) {
			require.Equal(t, hrange{Route: "GET /a"}, hr, name)
		}
	}
}

func TestHandlerRange_GoSeparateRoutesKeepSeparateRanges(t *testing.T) {
	src := `package main

func main() {
	r.Get("/x", one)
	r.Post("/x", two)
}

func one(w http.ResponseWriter, r *http.Request) {
	a()
}

func two(w http.ResponseWriter, r *http.Request) {
	b()
	c()
}
`
	require.Equal(t, []hrange{{"GET /x", 8, 10}, {"POST /x", 12, 15}}, handlerRanges(extractRoutes(src, "go")))
}

// ---- JavaScript / TypeScript ------------------------------------------------------------

func TestHandlerRange_JSInline(t *testing.T) {
	src := `const app = express();
app.get('/a', (req, res) => {
  res.send('a');
});
app.post('/b', async (req, res) => {
  await work();
  res.send('b');
});
app.put('/c', auth, function (req, res) {
  res.send('c');
});
app.delete('/d', req => {
  go();
});
app.get('/e', (req, res) => res.send('e'));
app.get('/f', asyncHandler(async (req, res) => {
  res.send('f');
}));
app.get('/g', (req: Request, res: Response): void => {
  res.send('g');
});
`
	require.Equal(t, []hrange{
		{"DELETE /d", 12, 14},
		{"GET /a", 2, 4},
		{"GET /e", 15, 15},
		{"GET /f", 16, 18},
		{"GET /g", 19, 21},
		{"POST /b", 5, 8},
		{"PUT /c", 9, 11},
	}, handlerRanges(extractRoutes(src, "typescript")))
}

func TestHandlerRange_JSBracesInStringsTemplatesAndComments(t *testing.T) {
	src := "app.get('/a', (req, res) => {\n" +
		"  const s = '}}';\n" +
		"  const t = `}${ fn({ a: 1 }) }}`;\n" +
		"  // } stray\n" +
		"  /* } */\n" +
		"  res.send(s + t);\n" +
		"});\n" +
		"app.get('/b', function (req, res) {\n" +
		"  res.send(\"{\");\n" +
		"});\n"
	want := []hrange{{"GET /a", 1, 7}, {"GET /b", 8, 10}}
	require.Equal(t, want, handlerRanges(extractRoutes(src, "javascript")), "raw source")
	require.Equal(t, want, handlerRanges(extractRoutes(stripComments(src, "javascript"), "javascript")), "after stripComments")
}

func TestHandlerRange_JSNamed(t *testing.T) {
	src := `const app = express();
app.get('/a', listUsers);
app.get('/b', showUser);
app.get('/c', oneLiner);
app.get('/d', ctrl.list);
app.get('/e', imported);
app.get('/f', twice);

function listUsers(req, res) {
  const rows = db.all();
  res.json({ rows });
}

const showUser = async (req, res) => {
  res.json({});
};

const oneLiner = (req, res) => res.send('x');

function list(req, res) {
  res.send('not ctrl.list');
}

const { imported } = require('./handlers');

function twice() { a(); }
function twice() { b(); }
`
	require.Equal(t, []hrange{
		{"GET /a", 9, 12},
		{"GET /b", 14, 16},
		{"GET /c", 18, 18},
		{"GET /d", 0, 0}, // ctrl.list is a member of ctrl, not the function list
		{"GET /e", 0, 0}, // imported from another file
		{"GET /f", 0, 0}, // two declarations, no guess
	}, handlerRanges(extractRoutes(src, "javascript")))
}

func TestHandlerRange_JSNestedAndUnbalanced(t *testing.T) {
	nested := `app.get('/a', (req, res) => {
  items.forEach((i) => {
    if (i) {
      go();
    }
  });
  res.send();
});
app.get('/b', (req, res) => {
  z();
});
`
	require.Equal(t, []hrange{{"GET /a", 1, 8}, {"GET /b", 9, 11}}, handlerRanges(extractRoutes(nested, "javascript")))

	for name, src := range map[string]string{
		"body never closes":  "app.get('/a', (req, res) => {\n  if (x) {\n    y();\n});\n",
		"call never closes":  "app.get('/a', (req, res) => {\n  y();\n",
		"template unclosed":  "app.get('/a', (req, res) => {\n  const t = `oops;\n});\n",
		"named never closes": "app.get('/a', named);\nfunction named(req, res) {\n  if (x) {\n",
	} {
		for _, hr := range handlerRanges(extractRoutes(src, "javascript")) {
			require.Equal(t, hrange{Route: "GET /a"}, hr, name)
		}
	}
}

// ---- Python -----------------------------------------------------------------------------

func TestHandlerRange_PythonDecorated(t *testing.T) {
	src := `from fastapi import FastAPI

app = FastAPI()


@app.get("/a")
def a():
    x = 1
    return x


@app.post("/b")
async def b(
    item: Item,
    db: Session = Depends(get_db),
) -> Item:
    """Create.

text at column zero inside a docstring
    """
    def inner():
        return 1

    # trailing comment

    return inner()


@app.get("/c")
@limiter.limit("5/minute")
def c():
    return {
        "k": 1,
}


class Other:
    @app.get("/d")
    def d(self):
        return 1

    def not_a_route(self):
        return 2


@app.get("/e")
def e(): return 1
`
	require.Equal(t, []hrange{
		{"GET /a", 6, 9},
		{"GET /c", 29, 34},
		{"GET /d", 38, 40},
		{"GET /e", 46, 47},
		{"POST /b", 12, 26},
	}, handlerRanges(extractRoutes(src, "python")))
	// A comment-stripped file lands on the same lines.
	require.Equal(t, handlerRanges(extractRoutes(src, "python")), handlerRanges(extractRoutes(stripComments(src, "python"), "python")))
}

func TestHandlerRange_PythonDecoratorWithoutFunctionAndFileEnd(t *testing.T) {
	// No def follows: no range. A def that runs to the end of the file stops at the file.
	require.Equal(t, []hrange{{"GET /a", 0, 0}}, handlerRanges(extractRoutes("@app.get(\"/a\")\nx = 1\n", "python")))
	got := handlerRanges(extractRoutes("@app.get(\"/a\")\ndef a():\n    return 1", "python"))
	require.Equal(t, []hrange{{"GET /a", 1, 3}}, got)
}

// ---- Spring / Kotlin --------------------------------------------------------------------

func TestHandlerRange_SpringMethods(t *testing.T) {
	src := `package demo;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/{id}")
    public User get(@PathVariable Long id) {
        String s = "}";
        char c = '{';
        if (id > 0) {
            return svc.find(id);
        }
        return null;
    }

    @PostMapping("/new")
    public User create(@RequestBody User u) { return svc.save(u); }

    @DeleteMapping("/x")
    void abstractOne();
}
`
	require.Equal(t, []hrange{
		{"DELETE /api/users/x", 0, 0}, // no body
		{"GET /api/users/{id}", 7, 15},
		{"POST /api/users/new", 17, 18},
	}, handlerRanges(extractRoutes(src, "java")))
}

func TestHandlerRange_KotlinMethods(t *testing.T) {
	src := `@RestController
class Ctl {
    @GetMapping("/k")
    fun k(): String {
        return "}"
    }

    @GetMapping("/expr")
    fun expr() = "x"
}
`
	require.Equal(t, []hrange{{"GET /expr", 0, 0}, {"GET /k", 3, 6}}, handlerRanges(extractRoutes(src, "kotlin")))
}

// ---- Bounds -----------------------------------------------------------------------------

// Whatever the source, a range is empty or lies within the file in order.
func TestHandlerRange_NeverExceedsTheFile(t *testing.T) {
	srcs := map[string][]string{
		"go": {
			"r.Get(\"/a\", func(w http.ResponseWriter, r *http.Request) {}",
			"r.Get(\"/a\", func(w http.ResponseWriter, r *http.Request) {\n}\n\n\n",
			"r.Get(\"/a\", func(w http.ResponseWriter, r *http.Request) {",
		},
		"javascript": {
			"app.get('/a', (req, res) => {",
			"app.get('/a', (req, res) => {})",
			"app.get('/a', (req, res) => res.send())\n\n",
		},
		"python": {"@app.get(\"/a\")\ndef a():", "@app.get(\"/a\")\ndef a():\n\n\n"},
		"java":   {"@GetMapping(\"/a\")\nString a() {", "@GetMapping(\"/a\")\nString a() {}\n\n\n"},
	}
	for lang, list := range srcs {
		for _, src := range list {
			total := strings.Count(src, "\n") + 1
			for _, r := range extractRoutes(src, lang) {
				if r.hStart == 0 && r.hEnd == 0 {
					continue
				}
				require.GreaterOrEqual(t, r.hStart, 1, "%s %q", lang, src)
				require.LessOrEqual(t, r.hStart, r.hEnd, "%s %q", lang, src)
				require.LessOrEqual(t, r.hEnd, total, "%s %q", lang, src)
			}
		}
	}
}

// ---- Properties -------------------------------------------------------------------------

func TestAddRouteSites_HandlerRangeProperties(t *testing.T) {
	with := route{method: "GET", path: "/v1/a", handler: "a", start: 4, end: 9, registered: 4, hStart: 5, hEnd: 9}
	without := route{method: "GET", path: "/v1/b", handler: "b", start: 3, end: 3, registered: 3}
	props := map[string]map[string]any{}
	addRouteSites([]routeSite{
		{key: "GET /v1/a", file: "a.go", language: "go", route: with},
		{key: "GET /v1/b", file: "b.go", language: "go", route: without},
	}, func(_ CrossRepoEdge, n Node) { props[n.Name] = n.Properties })
	require.Equal(t, 5, props["GET /v1/a"]["handlerStartLine"])
	require.Equal(t, 9, props["GET /v1/a"]["handlerEndLine"])
	require.NotContains(t, props["GET /v1/b"], "handlerStartLine", "an unresolved handler carries no range")
	require.NotContains(t, props["GET /v1/b"], "handlerEndLine")
}

// End to end through the collector: the range reaches the node as integers, and a handler
// that lives in another file carries none.
func TestCollectContracts_RouteNodeCarriesHandlerRange(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "api"), 0o755))
	src := `package api

import "github.com/go-chi/chi/v5"

func Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/v1/widgets", func(w http.ResponseWriter, r *http.Request) {
		// a } in a comment
		list(w)
	})
	r.Get("/v1/gadgets", gadgets.List)
	return r
}
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "api", "routes.go"), []byte(src), 0o644))
	files := &fileStats{files: []*FileRecord{{Path: "api/routes.go", Language: "go"}}}
	b := NewBuilder(Tool{Name: "test", Version: "dev"}, Target{RepoID: "acme/demo", RootPath: dir}, time.Now())
	st := collectContracts(b, dir, files, nil, Target{RepoID: "acme/demo"})
	byName := map[string]Node{}
	for _, n := range st.nodes {
		if n.Kind == "route" {
			byName[n.Name] = n
		}
	}
	w, ok := byName["GET /v1/widgets"]
	require.True(t, ok)
	require.Equal(t, 7, w.Properties["handlerStartLine"])
	require.Equal(t, 10, w.Properties["handlerEndLine"])
	g, ok := byName["GET /v1/gadgets"]
	require.True(t, ok)
	require.Equal(t, "gadgets.List", g.Properties["handler"])
	require.NotContains(t, g.Properties, "handlerStartLine")
	require.NotContains(t, g.Properties, "handlerEndLine")
}
