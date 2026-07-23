package analyze

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulnetix/cli/v3/internal/reachability"
)

func TestRunGraphOnlyCollectsScannerGraphSurfaces(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "main.tf", `
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}
resource "aws_s3_bucket" "logs" {}
module "network" {
  source = "app.terraform.io/acme/network/aws"
}
`)
	writeFixture(t, root, "Chart.yaml", `
apiVersion: v2
name: payments
dependencies:
  - name: redis
    version: 18.0.0
    repository: oci://ghcr.io/acme/charts
`)
	writeFixture(t, root, "deploy.yaml", `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: ghcr.io/acme/api:1.2.3
`)
	writeFixture(t, root, "Dockerfile", "FROM public.ecr.aws/docker/library/alpine:3.20\n")
	writeFixture(t, root, ".npmrc", "registry=https://npm.pkg.github.com\n")
	writeFixture(t, root, "package.json", `{"name":"demo","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}`)

	report, _, err := RunGraphOnly(Tool{Name: "vulnetix-scan-graph", Version: "dev"}, Options{
		Path:       root,
		NoGit:      true,
		NoTrust:    true,
		NoForge:    true,
		Silent:     true,
		MaxCommits: 1,
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, report.Graph)

	kinds := map[string]bool{}
	for _, e := range report.Graph.CrossRepoEdges {
		kinds[e.JoinKind] = true
	}
	for _, kind := range []string{
		"package",
		"iac_resource",
		"terraform_provider",
		"terraform_registry",
		"terraform_module",
		"helm_chart",
		"helm_registry",
		"container_image",
		"container_registry",
		"npm_registry",
	} {
		require.Truef(t, kinds[kind], "missing graph join kind %s", kind)
	}
}

func TestCollectSymbolsAddsResolvedCallEdges(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "go.mod", "module example.com/app\n")
	writeFixture(t, root, "cmd/app/main.go", `
package main

import "example.com/app/internal/util"

type service struct{}

func Handler() {
	helper()
	var s service
	s.Serve()
	util.Shared()
}

func helper() {}

func (s service) Serve() {}
`)
	writeFixture(t, root, "internal/util/util.go", `
package util

func Shared() {}
`)

	files := &fileStats{files: []*FileRecord{
		{ID: "file-cmd-app-main.go", Type: "file", Path: "cmd/app/main.go", Language: "go"},
		{ID: "file-internal-util-util.go", Type: "file", Path: "internal/util/util.go", Language: "go"},
	}}
	b := newTestBuilder()

	st := collectSymbols(b, root, files, "example.com/app", Options{}, reporter{})
	graph := buildGraph(Target{RepoID: "github.com~vulnetix~call-fixture"}, files, nil, nil, st, nil, nil, nil)
	b.SetGraph(graph)
	report, body, err := b.Finish(time.Now())
	require.NoError(t, err)
	require.NoError(t, ValidateReport(body))

	requireCallEdge(t, graph, "function:cmd/app/main.go:Handler", "function:cmd/app/main.go:helper", "lexical")
	requireCallEdge(t, graph, "function:cmd/app/main.go:Handler", "method:cmd/app/main.go:Serve", "heuristic")
	requireCallEdge(t, graph, "function:cmd/app/main.go:Handler", "function:internal/util/util.go:Shared", "import")

	var callsMetric *Metric
	for i := range report.Metrics {
		if report.Metrics[i].ID == "graph.calls.resolved" {
			callsMetric = &report.Metrics[i]
			break
		}
	}
	require.NotNil(t, callsMetric)
	require.Equal(t, float64(3), callsMetric.Value)
	require.Len(t, callsMetric.EvidenceRefs, 3)
}

func TestCallQueriesCompile(t *testing.T) {
	engine := reachability.NewEngine()
	for lang, query := range callQueries {
		t.Run(string(lang), func(t *testing.T) {
			_, err := engine.Run(context.Background(), lang, []byte{}, query)
			require.NoError(t, err)
		})
	}
}

func requireCallEdge(t *testing.T, graph *Graph, from, to, resolution string) {
	t.Helper()
	for _, edge := range graph.Edges {
		if edge.Kind == "calls" && edge.From == from && edge.To == to {
			require.Equal(t, resolution, edge.Resolution)

			return
		}
	}
	require.Failf(t, "missing call edge", "from %s to %s", from, to)
}

func writeFixture(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
}
