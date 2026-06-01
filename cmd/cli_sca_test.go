package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

func TestEnrichCliEnvForSCAResolvesSourceFilesFromScanRoot(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"dependencies":{"yaml":"2.6.1"}}`)
	mustWrite(t, filepath.Join(root, "yarn.lock"), `"yaml@npm:^2.6.1":
  version: 2.6.1
  resolution: "yaml@npm:2.6.1"
`)

	env := vdb.CliEnv{}
	enrichCliEnvForSCA(&env, root, []scan.ScopedPackage{
		{Name: "yaml", Version: "2.6.1", Ecosystem: "npm", SourceFile: "./package.json"},
		{Name: "yaml", Version: "2.6.1", Ecosystem: "npm", SourceFile: "./yarn.lock"},
	}, nil)

	assert.Len(t, env.Manifests, 2)
	assert.Equal(t, "package.json", env.Manifests[0].Path)
	assert.Equal(t, "npm", env.Manifests[0].Ecosystem)
	assert.Equal(t, "yarn.lock", env.Manifests[1].Path)
	assert.True(t, env.Manifests[1].IsLock)

	assert.Len(t, env.PackageManagers, 1)
	assert.Equal(t, "npm", env.PackageManagers[0].Ecosystem)
	assert.Equal(t, "package.json", env.PackageManagers[0].Manifest)

	var foundYarn bool
	for _, c := range env.Capabilities {
		if c.Binary == "yarn" {
			foundYarn = true
			assert.Equal(t, "npm", c.Ecosystem)
			assert.Equal(t, "binary:yarn", c.CapabilityName)
			assert.True(t, c.Authoritative)
		}
	}
	assert.True(t, foundYarn, "expected yarn capability from yarn.lock")
}

func TestEnrichCliEnvForSCASkipsExternalCDXSourceFiles(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "sbom.cdx.json"), `{"bomFormat":"CycloneDX","components":[]}`)

	env := vdb.CliEnv{}
	enrichCliEnvForSCA(&env, root, []scan.ScopedPackage{
		{Name: "yaml", Version: "2.6.1", Ecosystem: "npm", SourceFile: "./sbom.cdx.json"},
	}, nil)

	assert.Empty(t, env.Manifests)
	assert.Empty(t, env.PackageManagers)
	assert.Empty(t, env.Capabilities)
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
