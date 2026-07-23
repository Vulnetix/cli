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

func TestCollectInfrastructure_EnrichesTerraformResourceFromState(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "main.tf", `
resource "aws_s3_bucket" "logs" {}
resource "aws_iam_access_key" "ci" {}
`)
	writeFixture(t, root, "terraform.tfstate", `{
  "version": 4,
  "resources": [
    {
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "logs",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [{
        "attributes": {
          "id": "vulnetix-logs",
          "arn": "arn:aws:s3:::vulnetix-logs",
          "bucket": "vulnetix-logs",
          "password": "not-stored"
        }
      }]
    },
    {
      "mode": "managed",
      "type": "aws_iam_access_key",
      "name": "ci",
      "instances": [{
        "attributes": {
          "id": "AKIAIOSFODNN7EXAMPLE",
          "secret": "not-stored"
        }
      }]
    }
  ]
}`)

	var edges []CrossRepoEdge
	nodes := map[string]Node{}
	collectInfrastructure(root, func(e CrossRepoEdge, n Node) {
		edges = append(edges, e)
		nodes[n.ID] = n
	})

	bucket := nodes["iac_resource:terraform:aws_s3_bucket:logs"]
	require.Equal(t, "arn:aws:s3:::vulnetix-logs", bucket.QualifiedName)
	require.Equal(t, "arn:aws:s3:::vulnetix-logs", bucket.Properties["cloudIdentifier"])
	require.Equal(t, "aws", bucket.Properties["cloudProvider"])
	require.NotContains(t, bucket.Properties, "password")

	ids, ok := bucket.Properties["cloudIdentifiers"].(map[string]string)
	require.True(t, ok)
	require.Equal(t, "arn:aws:s3:::vulnetix-logs", ids["awsArn"])
	require.Equal(t, "vulnetix-logs", ids["id"])

	byLocalNode := map[string]CrossRepoEdge{}
	for _, edge := range edges {
		byLocalNode[edge.LocalNodeID] = edge
	}
	require.Equal(t, "arn:aws:s3:::vulnetix-logs", byLocalNode[bucket.ID].JoinKey)

	accessKey := nodes["iac_resource:terraform:aws_iam_access_key:ci"]
	require.Empty(t, accessKey.QualifiedName)
	require.NotContains(t, accessKey.Properties, "cloudIdentifiers")
}

func TestCollectInfrastructure_AddsTerraformStateOnlyModuleResources(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "main.tf", `
module "network" {
  source = "app.terraform.io/acme/network/aws"
}
`)
	writeFixture(t, root, "terraform.tfstate", `{
  "values": {
    "root_module": {
      "child_modules": [{
        "address": "module.network",
        "resources": [{
          "address": "module.network.aws_sqs_queue.events",
          "mode": "managed",
          "type": "aws_sqs_queue",
          "name": "events",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "values": {
            "id": "https://sqs.ap-southeast-2.amazonaws.com/123456789012/events",
            "arn": "arn:aws:sqs:ap-southeast-2:123456789012:events",
            "name": "events"
          }
        }]
      }]
    }
  }
}`)

	nodes := map[string]Node{}
	edges := map[string]CrossRepoEdge{}
	collectInfrastructure(root, func(e CrossRepoEdge, n Node) {
		nodes[n.ID] = n
		edges[n.ID] = e
	})

	id := "iac_resource:terraform:module.network.aws_sqs_queue.events"
	node := nodes[id]
	require.Equal(t, "arn:aws:sqs:ap-southeast-2:123456789012:events", node.QualifiedName)
	require.Equal(t, true, node.Properties["stateOnly"])
	require.Equal(t, "sqs", node.Properties["awsService"])
	require.Equal(t, "arn:aws:sqs:ap-southeast-2:123456789012:events", edges[id].JoinKey)
}

func TestCollectInfrastructure_AddsTerraformOutputIdentifiersAndSkipsSensitiveOutputs(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "terraform-outputs.json", `{
  "queue_arn": {
    "sensitive": false,
    "type": "string",
    "value": "arn:aws:sqs:ap-southeast-2:123456789012:events"
  },
  "queue_alias": {
    "sensitive": false,
    "type": "string",
    "value": "arn:aws:sqs:ap-southeast-2:123456789012:events"
  },
  "vpc_id": {
    "sensitive": false,
    "type": "string",
    "value": "vpc-0123abcdef"
  },
  "db_password": {
    "sensitive": true,
    "type": "string",
    "value": "not-stored"
  }
}`)

	nodes := map[string]Node{}
	edges := map[string]CrossRepoEdge{}
	queueARNNodes := 0
	collectInfrastructure(root, func(e CrossRepoEdge, n Node) {
		nodes[n.ID] = n
		edges[n.ID] = e
		if n.QualifiedName == "arn:aws:sqs:ap-southeast-2:123456789012:events" {
			queueARNNodes++
		}
	})

	id := "iac_resource:" + terraformOutputNodeKey(terraformOutputIdentity{
		Name:    "queue_arn",
		Primary: "arn:aws:sqs:ap-southeast-2:123456789012:events",
	})
	node := nodes[id]
	require.Equal(t, "queue_arn", node.Name)
	require.Equal(t, "arn:aws:sqs:ap-southeast-2:123456789012:events", node.QualifiedName)
	require.Equal(t, true, node.Properties["outputOnly"])
	require.Equal(t, "arn:aws:sqs:ap-southeast-2:123456789012:events", edges[id].JoinKey)
	require.Equal(t, 1, queueARNNodes)

	vpc := nodes["iac_resource:"+terraformOutputNodeKey(terraformOutputIdentity{Name: "vpc_id", Primary: "vpc-0123abcdef"})]
	require.Equal(t, "vpc-0123abcdef", vpc.QualifiedName)
	require.Equal(t, "aws", vpc.Properties["cloudProvider"])

	require.NotContains(t, nodes, "iac_resource:"+terraformOutputNodeKey(terraformOutputIdentity{Name: "db_password", Primary: "not-stored"}))
}

func TestCollectInfrastructure_EnrichesTerraformAzureAndGCPIdentifiers(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "main.tf", `
resource "azurerm_storage_account" "logs" {}
resource "google_compute_network" "net" {}
`)
	writeFixture(t, root, "terraform.tfstate", `{
  "values": {
    "root_module": {
      "resources": [{
        "address": "azurerm_storage_account.logs",
        "mode": "managed",
        "type": "azurerm_storage_account",
        "name": "logs",
        "provider_name": "registry.terraform.io/hashicorp/azurerm",
        "values": {
          "id": "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/logsacct",
          "primary_access_key": "not-stored"
        }
      }, {
        "address": "google_compute_network.net",
        "mode": "managed",
        "type": "google_compute_network",
        "name": "net",
        "provider_name": "registry.terraform.io/hashicorp/google",
        "values": {
          "self_link": "https://www.googleapis.com/compute/v1/projects/vdb-prod/global/networks/net",
          "project": "vdb-prod"
        }
      }]
    }
  }
}`)

	nodes := map[string]Node{}
	collectInfrastructure(root, func(_ CrossRepoEdge, n Node) {
		nodes[n.ID] = n
	})

	azure := nodes["iac_resource:terraform:azurerm_storage_account:logs"]
	require.Equal(t, "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/logsacct", azure.QualifiedName)
	require.Equal(t, "azure", azure.Properties["cloudProvider"])
	require.Equal(t, "sub-123", azure.Properties["azureSubscriptionId"])
	require.Equal(t, "rg-prod", azure.Properties["azureResourceGroup"])
	require.NotContains(t, azure.Properties, "primary_access_key")

	gcp := nodes["iac_resource:terraform:google_compute_network:net"]
	require.Equal(t, "https://www.googleapis.com/compute/v1/projects/vdb-prod/global/networks/net", gcp.QualifiedName)
	require.Equal(t, "gcp", gcp.Properties["cloudProvider"])
	require.Equal(t, "vdb-prod", gcp.Properties["gcpProject"])
}
