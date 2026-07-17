package analyze

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
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

func writeFixture(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
}
