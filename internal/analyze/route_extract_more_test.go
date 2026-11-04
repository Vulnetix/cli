package analyze

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// keysOf is "METHOD path" for each route, sorted.
func keysOf(rs []route) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.method+" "+r.path)
	}
	sort.Strings(out)

	return out
}

func TestNestControllersPrefixTheirMethods(t *testing.T) {
	src := `import { Controller, Get, Post, Delete } from '@nestjs/common';

@Controller('users')
export class UsersController {
  @Get()
  list() { return [] }

  @Get(':id')
  one() {}

  @Post()
  create() {}
}

@Controller()
export class HealthController {
  @Get('health')
  ok() {}
  @Delete('cache/:key')
  drop() {}
}
`
	src = stripComments(src, "typescript")
	require.True(t, servesHTTP(src, "typescript"))
	require.True(t, servesHTTP(src, "tsx"), "a .tsx file with the same code is a server too")
	require.Equal(t, []string{"DELETE /cache/:key", "GET /health", "GET /users", "GET /users/:id", "POST /users"},
		keysOf(extractRoutes(src, "typescript")))
}

func TestHonoAppsAreServers(t *testing.T) {
	src := "import { Hono } from 'hono'\nconst app = new Hono()\napp.get('/v1/items', (c) => c.json([]))\napp.post('/v1/items', h)\n"
	require.True(t, servesHTTP(src, "typescript"))
	require.Equal(t, []string{"GET /v1/items", "POST /v1/items"}, keysOf(extractRoutes(src, "typescript")))
}

func TestDjangoURLConfs(t *testing.T) {
	src := `from django.urls import path, include, re_path
from . import views

urlpatterns = [
    path('users/', views.user_list),
    path('users/<int:pk>/', views.user_detail, name='user-detail'),
    path('api/', include('api.urls')),
    re_path(r'^legacy/(?P<id>\d+)/$', views.legacy),
]
`
	src = stripComments(src, "python")
	require.True(t, servesHTTP(src, "python"))
	rs := extractRoutes(src, "python")
	require.Equal(t, []string{"ANY /users/", "ANY /users/{pk}/"}, keysOf(rs), "include() is another file's routes, re_path is a regex")
	require.Equal(t, "views.user_detail", rs[1].handler)
	require.Equal(t, 6, rs[1].registered)
	// path() outside a URLconf is not a route.
	require.Empty(t, extractDjangoRoutes("p = path('x/', view)\n"))
}

func TestAiohttpRegistrations(t *testing.T) {
	src := `from aiohttp import web
routes = web.RouteTableDef()

@routes.get('/v1/status')
async def status(request): ...

app = web.Application()
app.router.add_get('/v1/items', items)
app.router.add_route('POST', '/v1/items', create)
app.add_routes([web.delete('/v1/items/{id}', drop), web.view('/v1/things', Things)])
`
	src = stripComments(src, "python")
	require.True(t, servesHTTP(src, "python"))
	require.Equal(t, []string{"ANY /v1/things", "DELETE /v1/items/{id}", "GET /v1/items", "GET /v1/status", "POST /v1/items"},
		keysOf(extractRoutes(src, "python")))
}

func TestKtorRoutingNestsRoutePrefixes(t *testing.T) {
	src := `fun Application.module() {
    routing {
        get("/health") { call.respondText("ok") }
        route("/api") {
            route("/v1") {
                get("/users") {
                    val q = call.parameters.get("q")
                    call.respond(users)
                }
                post { call.respond(HttpStatusCode.Created) }
            }
        }
    }
}
`
	src = stripComments(src, "kotlin")
	require.True(t, servesHTTP(src, "kotlin"))
	rs := extractRoutes(src, "kotlin")
	require.Equal(t, []string{"GET /api/v1/users", "GET /health", "POST /api/v1"}, keysOf(rs), "parameters.get is not a route")
	for _, r := range rs {
		if r.path == "/api/v1/users" {
			require.Equal(t, 6, r.hStart)
			require.Equal(t, 9, r.hEnd)
		}
	}
}

func TestRailsRoutes(t *testing.T) {
	src := `Rails.application.routes.draw do
  get '/health', to: 'health#show'
  resources :sessions, only: [:create, :destroy]
  namespace :api do
    scope 'v1' do
      resources :users, except: [:new, :edit] do
        resources :posts, only: :index
      end
      resource :profile, only: [:show]
      post 'imports', to: 'imports#create'
    end
  end
end
`
	require.True(t, servesHTTP(src, "ruby"))
	got := keysOf(extractRoutes(stripComments(src, "ruby"), "ruby"))
	require.Equal(t, []string{
		"DELETE /api/v1/users/{id}", "DELETE /sessions/{id}",
		"GET /api/v1/profile", "GET /api/v1/users", "GET /api/v1/users/{id}", "GET /api/v1/users/{user_id}/posts",
		"GET /health",
		"PATCH /api/v1/users/{id}",
		"POST /api/v1/imports", "POST /api/v1/users", "POST /sessions",
		"PUT /api/v1/users/{id}",
	}, got)
}

func TestSinatraDefAndIfDoNotCloseARoutePrefix(t *testing.T) {
	src := `require 'sinatra'

helpers do
  def admin?
    if session[:admin]
      true
    end
  end
end

get '/v1/items' do
  json items
end

post '/v1/items' do
  halt 403 unless admin?
end
`
	require.True(t, servesHTTP(src, "ruby"))
	require.Equal(t, []string{"GET /v1/items", "POST /v1/items"}, keysOf(extractRoutes(stripComments(src, "ruby"), "ruby")))
}

// Vue's useRouter( and createRouter( are client code; only a router constructor at the
// start of a token is a server signal.
func TestVueRouterIsNotAServer(t *testing.T) {
	client := "import { useRouter } from 'vue-router'\nconst router = useRouter()\nconst r = createRouter({ history })\nawait fetch.get('/api/site/v1/config')\n"
	require.False(t, servesHTTP(client, "typescript"))
	require.True(t, servesHTTP("const r = express.Router()\nr.get('/x', h)\n", "typescript"))
	require.True(t, servesHTTP("const router = new Router({ prefix: '/v1' })\n", "javascript"))
	require.True(t, servesHTTP("const app = express()\n", "javascript"))
}

// A Go route registered in main.go whose handler is declared in another package gets the
// handler's file and lines, and only when exactly one declaration matches.
func TestGoHandlersInAnotherFileAreResolved(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	}
	write("main.go", `package main

func main() {
	r := chi.NewRouter()
	r.Get("/v1/users", handler.ListUsers(deps))
	r.Post("/v1/users", h.Create)
	r.Get("/v1/health", health)
	r.Get("/v1/dup", handler.Dup(deps))
}

func health(w http.ResponseWriter, r *http.Request) {}
`)
	write("internal/handler/users.go", `package handler

// ListUsers returns the handler.
func ListUsers(deps *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows := deps.DB.Query("SELECT * FROM users WHERE id = " + r.URL.Query().Get("id"))
		_ = rows
	}
}

func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {
	_ = r
}
`)
	write("internal/handler/dup.go", "package handler\n\nfunc Dup(d *Deps) http.HandlerFunc { return nil }\n")
	write("internal/other/handler/dup.go", "package handler\n\nfunc Dup(d *Deps) http.HandlerFunc { return nil }\n")

	src := stripComments(mustRead(t, filepath.Join(root, "main.go")), "go")
	var sites []routeSite
	for _, r := range extractRoutes(src, "go") {
		sites = append(sites, routeSite{key: normaliseRoute(r.method, r.path), file: "main.go", language: "go", route: r})
	}
	resolveGoHandlers(root, []string{"main.go", "internal/handler/users.go", "internal/handler/dup.go", "internal/other/handler/dup.go"}, sites)
	got := map[string]route{}
	for _, s := range sites {
		got[s.route.method+" "+s.route.path] = s.route
	}
	list := got["GET /v1/users"]
	require.Equal(t, "internal/handler/users.go", list.handlerFile)
	require.Equal(t, 4, list.hStart)
	require.Equal(t, 9, list.hEnd)
	create := got["POST /v1/users"]
	require.Equal(t, "internal/handler/users.go", create.handlerFile, "the one method named Create")
	require.Equal(t, 11, create.hStart)
	health := got["GET /v1/health"]
	require.Empty(t, health.handlerFile, "a handler in the route's own file keeps no handlerFile")
	require.Positive(t, health.hStart)
	require.Empty(t, got["GET /v1/dup"].handlerFile, "two packages named handler declare Dup: ambiguous, not guessed")
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	require.NoError(t, err)

	return string(b)
}
