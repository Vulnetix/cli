// Package apispecs finds an organisation's OpenAPI and Swagger descriptions in
// a working tree and reads them through the one shared module
// (github.com/Vulnetix/vdb-openapi), so the CLI, the backend and the console
// all agree on what a document says whatever version it is written in.
//
// It is the engine behind `vulnetix api discover`. Finding specs in files is
// safe and needs no network: the command never sends a request to a host
// unless the user passes an explicit --url.
package apispecs

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Vulnetix/vdb-openapi/detect"
	"github.com/Vulnetix/vdb-openapi/load"
	"github.com/Vulnetix/vdb-openapi/oas"
)

// maxSpecBytes bounds a single file read, matching the module's default.
const maxSpecBytes = 32 << 20

// Found is one spec read from a file.
type Found struct {
	// Path is relative to the scanned root.
	Path     string
	Document *oas.Document
	// Raw is the file's bytes, uploaded unchanged so the server re-reads them.
	Raw []byte
}

// Discover walks root for spec files and reads each through vdb-openapi. A
// file whose name looks like a spec is always read; any other .json/.yaml
// under the size cap is sniffed first, so a spec named oddly is still found
// without parsing every manifest in the tree. Vendored and generated trees
// are skipped.
func Discover(root string) ([]Found, error) {
	fsys := os.DirFS(root)
	var out []Found
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != "." && detect.SkipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !detect.MaybeSpecFile(p) {
			return nil
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil || len(data) == 0 || len(data) > maxSpecBytes {
			return nil
		}
		if !detect.LikelySpecName(p) {
			if _, _, ok := load.Sniff(data, load.Options{}); !ok {
				return nil
			}
		}
		doc, err := load.LoadFile(fsys, p, load.Options{})
		if err != nil {
			return nil
		}
		out = append(out, Found{Path: filepath.ToSlash(p), Document: doc, Raw: data})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// Generators returns the spec-generating frameworks named in a dependency
// list (for example a go.mod or package.json's dependency names), so a repo
// that builds its spec at runtime is reported even when no file is committed.
func Generators(dependencyNames []string) []detect.Generator {
	seen := map[string]bool{}
	var out []detect.Generator
	for _, name := range dependencyNames {
		for _, g := range detect.Generators(name) {
			if !seen[g.Framework] {
				seen[g.Framework] = true
				out = append(out, g)
			}
		}
	}
	return out
}

// Summary is a one-line description of a found spec for the command's output.
func Summary(f Found) string {
	d := f.Document
	var b strings.Builder
	b.WriteString(f.Path)
	b.WriteString(": ")
	b.WriteString(string(d.Source.Format))
	b.WriteString(" ")
	b.WriteString(d.Source.SpecVersion)
	b.WriteString(", ")
	b.WriteString(plural(len(d.Operations), "operation"))
	if len(d.Losses) > 0 {
		b.WriteString(", ")
		b.WriteString(plural(len(d.Losses), "loss"))
	}
	return b.String()
}

func plural(n int, word string) string {
	s := itoa(n) + " " + word
	if n != 1 {
		// Summary pluralises "loss" as well as "operation".
		if strings.HasSuffix(word, "s") {
			s += "es"
		} else {
			s += "s"
		}
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
