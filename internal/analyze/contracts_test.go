package analyze

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Route normalisation is the entire reason a cross-repo route edge can exist. The server that
// declares /users/:id and the client that calls /users/{userId} are talking about the same
// endpoint, and they will only ever meet in the org graph if both sides collapse to the same
// string.
func TestNormaliseRoute(t *testing.T) {
	cases := []struct{ method, path, want string }{
		{"GET", "/v1/users", "GET /v1/users"},

		// Every dialect of a path parameter means the same thing, and none of them carry meaning
		// for matching — only their position does.
		{"GET", "/users/:id", "GET /users/{param}"},
		{"GET", "/users/{userId}", "GET /users/{param}"},
		{"GET", "/users/<int:user_id>", "GET /users/{param}"},
		{"GET", "/users/*", "GET /users/{param}"},

		{"GET", "/v1/users/:id/posts/:postId", "GET /v1/users/{param}/posts/{param}"},

		// A trailing slash is not a different endpoint.
		{"GET", "/v1/users/", "GET /v1/users"},

		// Query strings and fragments are not part of the route's identity.
		{"GET", "/v1/users?active=true", "GET /v1/users"},

		// Framework-agnostic handlers match any method.
		{"HANDLEFUNC", "/v1/users", "ANY /v1/users"},
		{"ALL", "/v1/users", "ANY /v1/users"},
	}

	for _, c := range cases {
		require.Equal(t, c.want, normaliseRoute(c.method, c.path), "%s %s", c.method, c.path)
	}
}

// Every service has a /health. If we published it, every repository would appear to consume
// every other repository's health check and the org graph would be an N×M mesh of edges that
// mean nothing. GitNexus hit exactly this and had to filter it out after the fact.
func TestNormaliseRoute_DropsNoise(t *testing.T) {
	for _, p := range []string{"/health", "/healthz", "/readyz", "/livez", "/metrics", "/ping", "/", ""} {
		require.Empty(t, normaliseRoute("GET", p), "%q is noise and must not be published", p)
	}

	// A route that is nothing but parameters matches everything and therefore identifies
	// nothing. Publishing it would link every repository with a catch-all to every other one.
	require.Empty(t, normaliseRoute("GET", "/:id"))
	require.Empty(t, normaliseRoute("GET", "/{a}/{b}"))
}

// A base-image change reaches everything that runs on it, which makes image edges some of the
// most load-bearing in an org graph. They only form if both sides spell the image the same
// way — so the tag comes off: acme/api:1.2.3 and acme/api:1.3.0 are the same image from the
// same repository, and an org graph that only linked exact tags would show almost no edges,
// and the ones it showed would be an accident of who deployed last.
func TestNormaliseImage(t *testing.T) {
	require.Equal(t, "golang", normaliseImage("golang:1.25-alpine"))
	require.Equal(t, "ghcr.io/acme/api", normaliseImage("ghcr.io/acme/api:1.2.3"))
	require.Equal(t, "ghcr.io/acme/api", normaliseImage("ghcr.io/acme/api@sha256:abc123"))

	// A registry port is not a tag.
	require.Equal(t, "registry.local:5000/acme/api", normaliseImage("registry.local:5000/acme/api:v1"))

	// A templated reference names nothing until it is expanded, and we cannot expand it.
	require.Empty(t, normaliseImage("${BASE_IMAGE}"))
	require.Empty(t, normaliseImage("$BASE"))
	require.Empty(t, normaliseImage("--platform=$BUILDPLATFORM"))

	// `FROM scratch` is not a dependency on anybody's image.
	require.Empty(t, normaliseImage("scratch"))
}

func TestDockerfileFromRefs_SkipsPlatformFlagAndInterpolatesArgs(t *testing.T) {
	src := `
ARG BASE_IMAGE=public.ecr.aws/docker/library/alpine:3.20
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
FROM --platform=${TARGETPLATFORM} $BASE_IMAGE AS runtime
FROM ${UNSET_IMAGE}
FROM builder
`
	refs := dockerfileFromRefs(src)
	require.Equal(t, []dockerFromRef{
		{Image: "golang:1.24-alpine", Stage: "builder"},
		{Image: "public.ecr.aws/docker/library/alpine:3.20", Stage: "runtime"},
		{Image: "${UNSET_IMAGE}"},
		{Image: "builder"},
	}, refs)
}

func TestCollectImages_DockerfilePlatformFlagIsNotAnImage(t *testing.T) {
	root := t.TempDir()
	body := `
ARG BASE_IMAGE=public.ecr.aws/docker/library/alpine:3.20
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
FROM --platform=${TARGETPLATFORM} $BASE_IMAGE
`
	require.NoError(t, os.WriteFile(filepath.Join(root, "Dockerfile"), []byte(body), 0o644))

	edges := []CrossRepoEdge{}
	nodes := []Node{}
	collectImages(root, func(e CrossRepoEdge, n Node) {
		edges = append(edges, e)
		nodes = append(nodes, n)
	})

	nodeIDs := map[string]bool{}
	joinKeys := map[string]bool{}
	for _, n := range nodes {
		nodeIDs[n.ID] = true
	}
	for _, e := range edges {
		joinKeys[e.JoinKey] = true
	}

	require.True(t, nodeIDs["container_image:golang"])
	require.True(t, nodeIDs["container_image:public.ecr.aws/docker/library/alpine"])
	require.False(t, nodeIDs["container_image:--platform=$buildplatform"])
	require.False(t, joinKeys["--platform=$buildplatform"])
}

func TestCollectImages_DockerfileStageAliasDoesNotHideInitialImage(t *testing.T) {
	root := t.TempDir()
	body := `
FROM golang:1.24-alpine AS golang
FROM golang AS build
`
	require.NoError(t, os.WriteFile(filepath.Join(root, "Dockerfile"), []byte(body), 0o644))

	nodes := []Node{}
	collectImages(root, func(_ CrossRepoEdge, n Node) {
		nodes = append(nodes, n)
	})

	nodeIDs := map[string]bool{}
	for _, n := range nodes {
		nodeIDs[n.ID] = true
	}

	require.True(t, nodeIDs["container_image:golang"])
}

// A file that merely *mentions* a framework is not a server. This test exists because the
// contract detector was publishing itself as an HTTP provider: its own doc comments contain
// example routes, and its own signal list contains the string "http.HandleFunc".
func TestServesHTTP_NotFooledByComments(t *testing.T) {
	realServer := `package main
		import "github.com/go-chi/chi/v5"
		func main() { r := chi.NewRouter(); r.Get("/v1/users", h) }`
	require.True(t, servesHTTP(realServer, "go"))

	client := `package main
		func fetch() { resp, _ := http.Get("https://api.example.com/v1/users") }`
	require.False(t, servesHTTP(client, "go"),
		"a client that calls a route is not a server that provides it — publishing it as a provider would invert the dependency")
}

func TestStripComments(t *testing.T) {
	src := `// r.Get("/v1/users", handler)
	code := 1 // trailing
	/* block
	   r.Post("/v1/things", h)
	*/
	real := 2`
	out := stripComments(src, "go")

	require.NotContains(t, out, "/v1/users", "an example in a doc comment is not a route anybody serves")
	require.NotContains(t, out, "/v1/things")
	require.Contains(t, out, "real := 2")

	py := `# @app.get("/v1/users")
	x = 1`
	require.NotContains(t, stripComments(py, "python"), "/v1/users")
}

// A mock server in a test does not serve an org route. Test files stand up HTTP handlers
// constantly; if we read them, every repository with an httptest server would appear to
// provide whatever paths its tests happen to use.
func TestIsTestPath(t *testing.T) {
	for _, p := range []string{
		"cmd/root_test.go",
		"src/api.test.ts",
		"src/api.spec.js",
		"tests/test_client.py",
		"spec/models/user_spec.rb",
		"internal/handler/testdata/fixture.go",
		"e2e/flow.ts",
	} {
		require.True(t, isTestPath(p), "%s is test code", p)
	}

	for _, p := range []string{
		"cmd/root.go",
		"src/api.ts",
		"internal/latest/thing.go", // "test" must not match as a substring of a real directory
	} {
		require.False(t, isTestPath(p), "%s is production code", p)
	}
}

// The workflow key has to be the exact string another repository writes in its `uses:`, or
// the edge never forms. It is built from the repo identity rather than guessed.
func TestWorkflowKey(t *testing.T) {
	target := Target{RepoID: "github.com~vulnetix~cli"}
	require.Equal(t, "vulnetix/cli/.github/workflows/release.yml",
		workflowKey(target, ".github/workflows/release.yml"))

	// A repo with no remote has no identity to publish under, so it publishes nothing rather
	// than publishing something wrong.
	require.Empty(t, workflowKey(Target{RepoID: "local~~cli"}, ".github/workflows/release.yml"))
}
