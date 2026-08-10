package lsp

import (
	"net/url"
	"path/filepath"
	"strings"
	"sync"
)

// Document is one open editor buffer.
//
// Text is the editor's version, which may differ from what is on disk: that is
// the entire point of holding it, because the user wants findings about what
// they are looking at, not about what they last saved.
type Document struct {
	URI        string
	LanguageID string
	Version    int
	Text       string
	// RelPath is the path relative to the workspace root, in slash form, which
	// is how the rule engine keys FileSet and FileContents.
	RelPath string
}

// DocumentStore holds the open buffers.
//
// Safe for concurrent use: the read loop mutates it on didOpen/didChange while
// scan goroutines read it.
type DocumentStore struct {
	mu   sync.RWMutex
	docs map[string]*Document
}

func NewDocumentStore() *DocumentStore {
	return &DocumentStore{docs: make(map[string]*Document, 16)}
}

func (s *DocumentStore) Open(uri, languageID string, version int, text, relPath string) *Document {
	doc := &Document{URI: uri, LanguageID: languageID, Version: version, Text: text, RelPath: relPath}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.docs[uri] = doc
	return doc
}

// Update replaces a document's text.
//
// A change for a document that was never opened is ignored rather than
// synthesised: the client is required to send didOpen first, and inventing a
// document from a change would hide a client bug behind a plausible-looking
// buffer with no language id and no path.
func (s *DocumentStore) Update(uri string, version int, text string) (*Document, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, ok := s.docs[uri]
	if !ok {
		return nil, false
	}
	doc.Version = version
	doc.Text = text
	return doc, true
}

func (s *DocumentStore) Close(uri string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.docs, uri)
}

func (s *DocumentStore) Get(uri string) (*Document, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	doc, ok := s.docs[uri]
	return doc, ok
}

// Snapshot returns relPath to text for every open document.
//
// A copy, because the result is handed to an evaluation that runs concurrently
// with further edits, and the rule engine must see a consistent picture rather
// than a map changing underneath it.
func (s *DocumentStore) Snapshot() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.docs))
	for _, doc := range s.docs {
		if doc.RelPath != "" {
			out[doc.RelPath] = doc.Text
		}
	}
	return out
}

// All returns a snapshot of every open document.
//
// The Document values are copied, so a caller can read them without holding the
// lock and without racing the read loop's next update.
func (s *DocumentStore) All() []Document {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Document, 0, len(s.docs))
	for _, doc := range s.docs {
		out = append(out, *doc)
	}
	return out
}

// Languages returns the distinct language ids currently open, which is what
// decides the rule subset worth compiling.
func (s *DocumentStore) Languages() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]bool, len(s.docs))
	for _, doc := range s.docs {
		if doc.LanguageID != "" {
			seen[doc.LanguageID] = true
		}
	}
	out := make([]string, 0, len(seen))
	for lang := range seen {
		out = append(out, lang)
	}
	return out
}

func (s *DocumentStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.docs)
}

// ── URI handling ─────────────────────────────────────────────────────────────

// URIToPath converts a file:// URI to a local filesystem path.
//
// Not merely stripping a prefix. Editors percent-encode spaces and non-ASCII,
// and on Windows send file:///c:/... with a leading slash before the drive
// letter. Getting either wrong produces a path that does not exist, and the
// resulting "file not found" points at the wrong thing entirely.
func URIToPath(uri string) (string, bool) {
	if !strings.HasPrefix(uri, "file://") {
		return "", false
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		return "", false
	}

	path := parsed.Path
	if path == "" {
		return "", false
	}

	// Windows: file:///c:/x has Path "/c:/x". The drive letter needs the
	// leading slash removed, but a UNC path must keep its shape.
	if len(path) > 2 && path[0] == '/' && path[2] == ':' {
		path = path[1:]
	}

	return filepath.FromSlash(path), true
}

// PathToURI converts a local path to a file:// URI.
func PathToURI(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	slashed := filepath.ToSlash(abs)
	if !strings.HasPrefix(slashed, "/") {
		// Windows drive letter.
		slashed = "/" + slashed
	}
	u := url.URL{Scheme: "file", Path: slashed}
	return u.String()
}

// RelPathFor returns doc's path relative to root, in slash form, and whether it
// is inside root at all.
//
// A document outside every workspace folder is not scanned: the rule engine
// keys everything on repository-relative paths, and a file from elsewhere would
// either escape the root with .. segments or collide with a real path.
func RelPathFor(root, uri string) (string, bool) {
	path, ok := URIToPath(uri)
	if !ok {
		return "", false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", false
	}
	rel = filepath.ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}
