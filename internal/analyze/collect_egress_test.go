package analyze

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// A tree with a host in each kind of file, plus the noise that must not survive.
func writeEgressFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	files := map[string]string{
		".github/workflows/release.yml": "steps:\n  - run: curl -sSL https://releases.acme-ci.io/install.sh | sh\n",
		"Dockerfile":                    "FROM base\nRUN wget https://mirror.acme-pkgs.net/tool.tar.gz\n",
		"terraform/dns.tf":              "resource \"aws_route53_record\" \"api\" {\n  name = \"api.acme-prod.dev\"\n}\n",
		".env.example":                  "WEBHOOK_URL=https://hooks.acme-chat.app/services/x\n",
		"internal/client.go": `package internal

import "github.com/vulnetix/cli/v3/internal/scan"

// See https://www.w3.org/TR/xml/ and https://en.wikipedia.org/wiki/HTTP for background.
const endpoint = "https://api.acme-payments.com/v1/charge"
const smtp = "mail.acme-relay.net:587"

func send(p *scan.Payload, resp *Response) string {
	return p.name + resp.data + t.run
}
`,
		"vendor/thirdparty/lib.go": "package lib\nconst x = \"https://vendored-should-be-skipped.com\"\n",
		"docs/notes.md":            "we might one day call https://markdown-not-scanned.com\n",
	}

	for rel, body := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	}

	return root
}

func collectedHosts(st *egressStats) map[string]*egressHost {
	out := map[string]*egressHost{}
	for _, h := range st.hosts {
		out[h.Host] = h
	}

	return out
}

func TestCollectEgressFindsHostsPerSourceClass(t *testing.T) {
	st := collectEgress(writeEgressFixture(t), nil)
	hosts := collectedHosts(st)

	require.Contains(t, hosts, "releases.acme-ci.io")
	require.Equal(t, []string{egressSourceCI}, sortedKeys(hosts["releases.acme-ci.io"].sources))

	require.Contains(t, hosts, "mirror.acme-pkgs.net")
	require.Equal(t, []string{egressSourceContainer}, sortedKeys(hosts["mirror.acme-pkgs.net"].sources))

	require.Contains(t, hosts, "api.acme-prod.dev")
	require.Equal(t, []string{egressSourceIaC}, sortedKeys(hosts["api.acme-prod.dev"].sources))

	require.Contains(t, hosts, "hooks.acme-chat.app")
	require.Equal(t, []string{egressSourceEnv}, sortedKeys(hosts["hooks.acme-chat.app"].sources))

	require.Contains(t, hosts, "api.acme-payments.com")
	require.Equal(t, []string{egressSourceCode}, sortedKeys(hosts["api.acme-payments.com"].sources))
	require.Equal(t, []string{"https"}, sortedKeys(hosts["api.acme-payments.com"].schemes))
	require.Equal(t, "internal/client.go", hosts["api.acme-payments.com"].FirstPath)
}

// The point of asking tree-sitter: a host passed to something that opens a
// socket is a destination, whatever else the file contains.
func TestCollectEgressCallSiteEvidence(t *testing.T) {
	root := t.TempDir()

	files := map[string]string{
		"internal/client.go": `package internal

import "net/http"

const metricID = "business.dependencies.total"

func fetch() {
	req, _ := http.NewRequest("GET", "https://api.acme-payments.com/v1/charge", nil)
	_ = req
	_ = metricID
}
`,
		"scripts/deploy.sh": `#!/bin/sh
GA_URL="https://telemetry.acme-deploy.io/collect"
curl -fsSL "$GA_URL" >/dev/null
`,
	}
	for rel, body := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	}

	hosts := collectedHosts(collectEgress(root, nil))

	require.Contains(t, hosts, "api.acme-payments.com")
	require.Equal(t, egressEvidenceCallSite, bestEvidence(hosts["api.acme-payments.com"].evidence))
	require.Contains(t, sortedKeys(hosts["api.acme-payments.com"].callees), "http.NewRequest")

	// One hop: the shell passes a variable, and the variable was assigned a URL.
	require.Contains(t, hosts, "telemetry.acme-deploy.io")
	require.Equal(t, egressEvidenceCallSite, bestEvidence(hosts["telemetry.acme-deploy.io"].evidence))
	require.Contains(t, sortedKeys(hosts["telemetry.acme-deploy.io"].callees), "curl")

	// `.total` is a real TLD. A metric id is still not a destination.
	require.NotContains(t, hosts, "business.dependencies.total")
}

// Structure, not text: an expression reference is not a value, and the key a
// value sits under is worth keeping.
func TestCollectEgressConfigIsParsedNotScanned(t *testing.T) {
	root := t.TempDir()

	files := map[string]string{
		".github/workflows/ci.yml": "jobs:\n  build:\n    steps:\n      - run: echo ${{ steps.scan.outputs.total }}\n      - name: push\n        registry: mirror.acme-pkgs.net\n",
		"terraform/rules.tf":       "resource \"cloudflare_ruleset\" \"r\" {\n  expression = \"(http.host eq \\\"acme-prod.dev\\\")\"\n  endpoint   = \"api.acme-prod.dev\"\n}\n",
		"Dockerfile":               "FROM ghcr.io/acme/base:1.2\nRUN apk add --no-cache curl\n",
	}
	for rel, body := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	}

	hosts := collectedHosts(collectEgress(root, nil))

	require.Contains(t, hosts, "mirror.acme-pkgs.net")
	require.Equal(t, []string{"jobs.build.steps.registry"},
		sortedKeys(hosts["mirror.acme-pkgs.net"].keyPaths))

	require.Contains(t, hosts, "api.acme-prod.dev")
	require.Contains(t, sortedKeys(hosts["api.acme-prod.dev"].keyPaths), "endpoint")

	require.Contains(t, hosts, "ghcr.io")
	require.Contains(t, sortedKeys(hosts["ghcr.io"].keyPaths), "from")

	// `${{ steps.scan.outputs.total }}` is a reference to a value, and `.total`
	// is a TLD. Reading the format rather than the text is what excludes it.
	require.NotContains(t, hosts, "steps.scan.outputs.total")
	// An HCL traversal inside a rule expression is not a hostname either.
	require.NotContains(t, hosts, "http.host")
}

func TestCollectEgressRejectsNoise(t *testing.T) {
	hosts := collectedHosts(collectEgress(writeEgressFixture(t), nil))

	require.NotContains(t, hosts, "www.w3.org", "a namespace in a comment is not a destination")
	require.NotContains(t, hosts, "en.wikipedia.org", "nor is a doc link")
	require.NotContains(t, hosts, "vendored-should-be-skipped.com", "vendor/ is never walked")
	require.NotContains(t, hosts, "install.sh", "a script in a URL path is not a host in Saint Helena")

	// .name, .data and .run are all real TLDs, which is why field access has to be
	// excluded structurally rather than by denylisting the words.
	require.NotContains(t, hosts, "p.name")
	require.NotContains(t, hosts, "resp.data")
	require.NotContains(t, hosts, "t.run")

	require.NotContains(t, hosts, "github.com", "an import path says where code came from")
}

// A literal that is nothing but a host is the one bare form source code can be
// trusted on — and it is how a mail relay or a broker gets configured.
func TestCollectEgressReadsHostOnlyLiterals(t *testing.T) {
	hosts := collectedHosts(collectEgress(writeEgressFixture(t), nil))

	require.Contains(t, hosts, "mail.acme-relay.net")
	require.Equal(t, []string{egressSourceCode}, sortedKeys(hosts["mail.acme-relay.net"].sources))
}

// A dependency that is not resolved from a registry is the same destination as
// one written in a file, and must land on the same node rather than beside it.
func TestCollectEgressMergesNonRegistryDependencies(t *testing.T) {
	deps := &depStats{deps: []*DependencyRecord{
		{Purl: "pkg:golang/viperhappenscope.com@v1.0.0", ManifestPath: "go.mod", Ecosystem: "golang"},
		{Purl: "pkg:npm/socket.io@4.7.5", ManifestPath: "package.json", Ecosystem: "npm"},
		{Purl: "pkg:golang/github.com/spf13/viper@v1.18.2", ManifestPath: "go.mod", Ecosystem: "golang"},
	}}

	hosts := collectedHosts(collectEgress(t.TempDir(), deps))

	require.Contains(t, hosts, "viperhappenscope.com")
	require.Equal(t, "pkg:golang/viperhappenscope.com@v1.0.0", hosts["viperhappenscope.com"].Purl)
	require.Equal(t, []string{egressSourceManifest}, sortedKeys(hosts["viperhappenscope.com"].sources))

	require.NotContains(t, hosts, "socket.io")
	require.NotContains(t, hosts, "github.com")
}

func TestEgressGraphNodesCarryProvenance(t *testing.T) {
	st := collectEgress(writeEgressFixture(t), nil)

	byID := map[string]Node{}
	for _, n := range st.graphNodes() {
		byID[n.ID] = n
	}

	node, ok := byID["egress_domain:api.acme-payments.com"]
	require.True(t, ok)
	require.Equal(t, "egress_domain", node.Kind)
	require.Equal(t, "api.acme-payments.com", node.Name)
	require.Equal(t, "internal/client.go", node.Properties["firstPath"])
	require.Equal(t, []string{egressSourceCode}, node.Properties["sources"])
	require.Greater(t, node.Properties["occurrences"], 0)
}

// The graph must say when it stopped looking. A silent cap reads as "these are
// all the hosts", which is the one thing it must never claim wrongly.
func TestCollectEgressReportsTheCap(t *testing.T) {
	root := t.TempDir()

	body := ""
	for i := range maxEgressHosts + 25 {
		body += "https://host" + strconv.Itoa(i) + ".acme-many.com/x\n"
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "hosts.yml"), []byte(body), 0o644))

	st := collectEgress(root, nil)
	require.True(t, st.truncated)
	require.Len(t, st.hosts, maxEgressHosts)
}
