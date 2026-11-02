package platformiac

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	configschemas "github.com/vulnetix/config-schemas"
)

// ConfigDir is the folder of Platform IaC documents in a repository.
const ConfigDir = ".vulnetix/config"

// WellKnownFile is a singleton document with a fixed path of its own.
type WellKnownFile struct {
	Path string
	Kind string
}

// WellKnown are the files read beside .vulnetix/config.
var WellKnown = []WellKnownFile{
	{Path: ".vulnetix/ai-firewall.yaml", Kind: "AiFirewallPolicy"},
	{Path: ".vulnetix/license-policy.yaml", Kind: "LicensePolicy"},
	{Path: ".vulnetix/license-exceptions.yaml", Kind: "LicenseExceptions"},
}

// WellKnownPath returns the well-known file for kind, or "".
func WellKnownPath(kind string) string {
	for _, w := range WellKnown {
		if w.Kind == kind {
			return w.Path
		}
	}
	return ""
}

// Document is one Platform IaC document and where it came from.
type Document struct {
	configschemas.Document
	Path  string
	Index int // 1-based position in its file
	// WellKnown marks a document read from a WellKnown file.
	WellKnown bool
}

// Options select what Discover reads.
type Options struct {
	// Root is the repository root; .vulnetix/config and the well-known files
	// are under it.
	Root string
	// Files are -f arguments: files, directories ("-" is Stdin). When set,
	// only they are read. A named file must hold documents; a named
	// directory is read like the config folder.
	Files []string
	Stdin io.Reader
	// IncludeWellKnown reads the WellKnown files too when Files is empty.
	IncludeWellKnown bool
	// Notes receives one line per skipped file (the -v note). Nil is silent.
	Notes io.Writer
}

// Discover returns the documents the options name, in a stable order:
// folder files sorted by path, then the well-known files.
func Discover(o Options) ([]Document, error) {
	if o.Root == "" {
		o.Root = "."
	}
	var docs []Document
	if len(o.Files) > 0 {
		for _, a := range o.Files {
			if a == "-" {
				ds, err := readFile("-", o.Stdin, true, o.Notes)
				if err != nil {
					return nil, err
				}
				docs = append(docs, ds...)
				continue
			}
			st, err := os.Stat(a)
			if err != nil {
				return nil, err
			}
			if st.IsDir() {
				ds, err := readFolder(a, o.Notes)
				if err != nil {
					return nil, err
				}
				docs = append(docs, ds...)
				continue
			}
			ds, err := readFile(a, nil, true, o.Notes)
			if err != nil {
				return nil, err
			}
			if err := checkWellKnown(o.Root, a, ds); err != nil {
				return nil, err
			}
			docs = append(docs, ds...)
		}
		return docs, nil
	}

	dir := filepath.Join(o.Root, filepath.FromSlash(ConfigDir))
	if _, err := os.Stat(dir); err == nil {
		ds, err := readFolder(dir, o.Notes)
		if err != nil {
			return nil, err
		}
		docs = append(docs, ds...)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if o.IncludeWellKnown {
		for _, w := range WellKnown {
			ds, err := readWellKnown(o.Root, w)
			if err != nil {
				return nil, err
			}
			docs = append(docs, ds...)
		}
	}
	return docs, nil
}

// readWellKnown reads one well-known file, if present. It must hold exactly
// documents of its kind.
func readWellKnown(root string, w WellKnownFile) ([]Document, error) {
	p := filepath.Join(root, filepath.FromSlash(w.Path))
	if _, err := os.Stat(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	ds, err := readWellKnownFile(p, w.Kind)
	if err != nil {
		return nil, err
	}
	for i := range ds {
		if ds[i].Kind != w.Kind {
			return nil, fmt.Errorf("%s holds a %s; %s is for %s only", p, ds[i].Kind, w.Path, w.Kind)
		}
		ds[i].WellKnown = true
	}
	return ds, nil
}

// readWellKnownFile reads a well-known file. A licence file written before
// documents carried apiVersion and kind (license.ParsePolicy still accepts
// one) is read as the file's kind, so an old repository keeps working.
func readWellKnownFile(p, kind string) ([]Document, error) {
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	decoded, err := configschemas.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	for i := range decoded {
		m, ok := decoded[i].Value.(map[string]any)
		if !ok {
			continue
		}
		_, hasAPI := m["apiVersion"]
		_, hasKind := m["kind"]
		if !hasAPI && !hasKind {
			m["apiVersion"] = APIVersion
			m["kind"] = kind
			decoded[i].Kind = kind
		}
	}
	var docs []Document
	for i, d := range decoded {
		switch c, k := Classify(d.Value); c {
		case IsDoc:
			docs = append(docs, Document{Document: d, Path: p, Index: i + 1})
		case UnknownKind:
			return nil, fmt.Errorf("%s (document %d): unknown kind %q", p, i+1, k)
		default:
			return nil, fmt.Errorf("%s is not a Platform IaC document (needs apiVersion: %s and kind: %s)", p, APIVersion, kind)
		}
	}
	return docs, nil
}

// checkWellKnown applies the well-known rule to a file named with -f that
// happens to be one.
func checkWellKnown(root, path string, ds []Document) error {
	abs, _ := filepath.Abs(path)
	for _, w := range WellKnown {
		wp, _ := filepath.Abs(filepath.Join(root, filepath.FromSlash(w.Path)))
		if abs != wp {
			continue
		}
		for _, d := range ds {
			if d.Kind != w.Kind {
				return fmt.Errorf("%s holds a %s; %s is for %s only", path, d.Kind, w.Path, w.Kind)
			}
		}
	}
	return nil
}

// readFolder walks a folder: YAML and JSON files holding documents are read,
// everything else is skipped (with a note).
func readFolder(dir string, notes io.Writer) ([]Document, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var docs []Document
	for _, p := range paths {
		switch strings.ToLower(filepath.Ext(p)) {
		case ".yaml", ".yml", ".json":
		default:
			note(notes, p, "not YAML or JSON")
			continue
		}
		ds, err := readFile(p, nil, false, notes)
		if err != nil {
			return nil, err
		}
		docs = append(docs, ds...)
	}
	return docs, nil
}

// readFile decodes one file. required means the file was asked for by name:
// it must hold documents. A folder file with none is skipped.
func readFile(p string, stdin io.Reader, required bool, notes io.Writer) ([]Document, error) {
	var raw []byte
	var err error
	if p == "-" {
		if stdin == nil {
			stdin = os.Stdin
		}
		raw, err = io.ReadAll(stdin)
	} else {
		raw, err = os.ReadFile(p)
	}
	if err != nil {
		return nil, err
	}
	decoded, derr := configschemas.Decode(bytes.NewReader(raw))
	if derr != nil {
		// Unparseable. A file that says it is a document is a broken one;
		// anything else in a folder is just not ours.
		if required || bytes.Contains(raw, []byte(APIVersion)) {
			return nil, fmt.Errorf("%s: %w", p, derr)
		}
		note(notes, p, "not YAML or JSON")
		return nil, nil
	}
	var docs []Document
	others := 0
	for i, d := range decoded {
		switch c, kind := Classify(d.Value); c {
		case IsDoc:
			docs = append(docs, Document{Document: d, Path: p, Index: i + 1})
		case UnknownKind:
			if kind == "" {
				return nil, fmt.Errorf("%s (document %d): %s document has no kind", p, i+1, APIVersion)
			}
			return nil, fmt.Errorf("%s (document %d): unknown kind %q (known: %s)", p, i+1, kind, strings.Join(Kinds(), ", "))
		default:
			others++
		}
	}
	switch {
	case len(docs) > 0 && others > 0:
		return nil, fmt.Errorf("%s mixes %s documents with other content; keep each in its own file", p, APIVersion)
	case len(docs) == 0 && required:
		return nil, fmt.Errorf("%s is not a Platform IaC document (needs apiVersion: %s and a known kind)", p, APIVersion)
	case len(docs) == 0:
		note(notes, p, "no "+APIVersion+" documents")
	}
	return docs, nil
}

func note(w io.Writer, p, why string) {
	if w != nil {
		fmt.Fprintf(w, "skipped %s: %s\n", p, why)
	}
}
