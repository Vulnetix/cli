package fix

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The install runs in the manifest's directory, so the command names the file
// by base name, and only a requirements file is ever given to `pip install -r`.
func TestPipCommandForManifestKinds(t *testing.T) {
	cases := map[string]string{
		"requirements.txt":         "pip install -r requirements.txt",
		"./requirements.txt":       "pip install -r requirements.txt",
		"api/requirements-dev.txt": "pip install -r requirements-dev.txt",
		"svc/requirements.in":      "pip install -r requirements.in",
		"pyproject.toml":           "pip install .",
		"./pyproject.toml":         "pip install .",
		"services/api/setup.py":    "pip install .",
		"setup.cfg":                "pip install .",
		"web/Pipfile":              "pipenv install",
	}
	for source, want := range cases {
		got := commandFor(FixCandidate{PackageName: "requests", Ecosystem: "pypi", SourceFile: source, Method: MethodDirectBump}, "2.34.2")
		require.Equal(t, want, got, source)
	}
}
