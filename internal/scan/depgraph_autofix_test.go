package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPopulateNpmLockEdgesRecordsDeclaredRanges(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "package-lock.json")
	err := os.WriteFile(lockPath, []byte(`{
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/parent": {
      "version": "1.0.0",
      "dependencies": {
        "child": "^1.2.0"
      },
      "peerDependencies": {
        "peer-child": "~2.0.0"
      }
    },
    "node_modules/child": { "version": "1.2.3" },
    "node_modules/peer-child": { "version": "2.0.1" }
  }
}`), 0o644)
	require.NoError(t, err)

	g := &DepGraph{}
	require.NoError(t, g.PopulateNpmLockEdges(lockPath))
	require.ElementsMatch(t, []string{"child", "peer-child"}, g.Edges["parent"])
	require.Equal(t, "^1.2.0", g.EdgeRanges["parent"]["child"])
	require.Equal(t, "~2.0.0", g.EdgeRanges["parent"]["peer-child"])
}
