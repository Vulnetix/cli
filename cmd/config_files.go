package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Some kinds (DetectionRule, AgentProfile, LibraryItem) name a text file with
// `file:` instead of carrying it as `body:`. The schema says the client reads
// the file and sends its text as the value, and that the server never reads a
// path, so before a plan or an apply every `file` in these documents becomes a
// `body`. The path is relative to the config root (the directory named with -f,
// else .vulnetix/config), then to the document's own directory.

// configFileKinds are the kinds whose `file` fields are configFile values.
var configFileKinds = map[string]bool{"DetectionRule": true, "AgentProfile": true, "LibraryItem": true}

// maxConfigFileBytes is the largest text a body takes (256 KiB); the schema
// limits differ per field, so this only stops reading an unbounded file.
const maxConfigFileBytes = 256 << 10

// inlineConfigFiles replaces every `file` in the documents of those kinds with
// the file's text as `body`. roots are the config roots, tried in order after
// the document's own directory.
func inlineConfigFiles(docs []configDocument, roots []string) error {
	for i := range docs {
		d := &docs[i]
		if !configFileKinds[d.Kind] {
			continue
		}
		spec, ok := d.Value.(map[string]any)["spec"]
		if !ok {
			continue
		}
		search := append(append([]string{}, roots...), filepath.Dir(d.Path))
		if err := inlineFilesIn(spec, search, d); err != nil {
			return fmt.Errorf("%s (document %d): %w", d.Path, d.Index, err)
		}
	}
	return nil
}

func inlineFilesIn(v any, roots []string, d *configDocument) error {
	switch t := v.(type) {
	case map[string]any:
		if name, ok := t["file"].(string); ok {
			if _, hasBody := t["body"]; hasBody {
				return fmt.Errorf("a value names both file and body")
			}
			text, err := readConfigFile(name, roots)
			if err != nil {
				return fmt.Errorf("file %q: %w", name, err)
			}
			t["body"] = text
			delete(t, "file")
		}
		for _, child := range t {
			if err := inlineFilesIn(child, roots, d); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range t {
			if err := inlineFilesIn(child, roots, d); err != nil {
				return err
			}
		}
	}
	return nil
}

// readConfigFile reads name, relative to the first root that holds it. A path
// that is absolute or climbs out of the root is refused, as is a symlink that
// leaves it, so a document in a pull request cannot make a plan read and send
// a file from elsewhere on the runner.
func readConfigFile(name string, roots []string) (string, error) {
	if !filepath.IsLocal(filepath.FromSlash(name)) {
		return "", fmt.Errorf("must be a relative path inside the config root")
	}
	for _, root := range roots {
		if root == "" {
			continue
		}
		full := filepath.Join(root, filepath.FromSlash(name))
		real, err := filepath.EvalSymlinks(full)
		if err != nil {
			continue
		}
		realRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		if rel, err := filepath.Rel(realRoot, real); err != nil || !filepath.IsLocal(rel) {
			return "", fmt.Errorf("resolves outside the config root")
		}
		st, err := os.Stat(real)
		if err != nil || st.IsDir() {
			continue
		}
		if st.Size() > maxConfigFileBytes {
			return "", fmt.Errorf("is %d bytes; at most %d", st.Size(), maxConfigFileBytes)
		}
		b, err := os.ReadFile(real)
		if err != nil {
			return "", err
		}
		if !utf8.Valid(b) {
			return "", fmt.Errorf("is not UTF-8 text")
		}
		return string(b), nil
	}
	return "", fmt.Errorf("not found under %s", strings.Join(nonEmpty(roots), ", "))
}

func nonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// configRoots are the directories a `file` is looked for in: each directory
// named with -f, then the default config directory.
func configRoots(files []string) []string {
	var roots []string
	for _, f := range files {
		if st, err := os.Stat(f); err == nil && st.IsDir() {
			roots = append(roots, f)
		}
	}
	return append(roots, defaultConfigDir)
}
