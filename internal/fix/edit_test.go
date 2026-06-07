package fix

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEditPackageJSONPreservesRangeOperator(t *testing.T) {
	content := `{
  "dependencies": {
    "left-pad": "^1.1.0",
    "other": "2.0.0"
  }
}`
	next, changed := editManifest(content, FixCandidate{
		PackageName: "left-pad",
		SourceFile:  "package.json",
		TargetVer:   "1.3.0",
	})
	require.True(t, changed)
	require.Contains(t, next, `"left-pad": "^1.3.0"`)
	require.Contains(t, next, `"other": "2.0.0"`)
}

func TestEditGoModBumpsRequireLine(t *testing.T) {
	content := "module example.test\n\nrequire github.com/acme/lib v1.2.0\n"
	next, changed := editManifest(content, FixCandidate{
		PackageName: "github.com/acme/lib",
		SourceFile:  "go.mod",
		TargetVer:   "1.4.0",
	})
	require.True(t, changed)
	require.Contains(t, next, "require github.com/acme/lib v1.4.0")
}
