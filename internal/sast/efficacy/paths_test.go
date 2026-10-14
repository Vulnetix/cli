package efficacy

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// The Go module proxy refuses to build a module zip in which two paths differ
// only by case, which makes `go install` of every release fail. Cases that
// need both spellings (src/Auth and src/auth) must use different names.
func TestCaseDirsDoNotCollideOnCaseInsensitiveFilesystems(t *testing.T) {
	seen := map[string]string{}
	err := filepath.WalkDir("../testdata", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		key := strings.ToLower(p)
		if prev, ok := seen[key]; ok && prev != p {
			t.Errorf("%s and %s differ only by case", prev, p)
		}
		seen[key] = p
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
