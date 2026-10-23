package fix

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyNpmOverridesPrefersPackageJSONNextToLockfile(t *testing.T) {
	dir := t.TempDir()
	// Overrides are now spliced into the text in the file's own layout (a minified
	// file stays minified), so the input is laid out the way the assertion reads.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte("{\n  \"dependencies\": {\n    \"parent\": \"1.0.0\"\n  }\n}\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"lockfileVersion":3}`), 0o644))

	err := applyNpmOverrides(FixBatch{
		Dir:        dir,
		SourceFile: "package-lock.json",
		Plans: []FixCandidate{{
			PackageName: "vulnerable-child",
			Ecosystem:   "npm",
			TargetVer:   "2.0.0",
		}},
	})

	require.NoError(t, err)
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	require.NoError(t, err)
	require.Contains(t, string(data), `"overrides"`)
	require.Contains(t, string(data), `"vulnerable-child": "2.0.0"`)
}
