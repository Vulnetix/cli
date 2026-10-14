package lint

import (
	"os"

	"golang.org/x/mod/modfile"
)

// Load parses a go.mod; the testdata module above is an input to its tests.
func Load(path string) (*modfile.File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return modfile.Parse(path, data, nil)
}
