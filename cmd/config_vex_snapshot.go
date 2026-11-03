package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// A VexSource with a `path` source is read by the CLI, never by the server:
// at scan time its documents apply locally, and `config apply` uploads a
// snapshot of them so the console shows the same suppressions. The upload
// replaces the source's last snapshot, so statements that left the files leave
// the server too, exactly as a fetched source's would.

const (
	// vexSnapshotMaxDocs and vexSnapshotMaxBytes are the server's limits on one
	// snapshot upload (api/internal/handler/vex_source.go).
	vexSnapshotMaxDocs  = 10
	vexSnapshotMaxBytes = 8 << 20
)

// vexSnapshotDocument is one document in the upload body: the bytes base64
// encoded with the hex sha256 of the raw bytes.
type vexSnapshotDocument struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Content string `json:"content"`
}

type vexSnapshotRequest struct {
	Documents []vexSnapshotDocument `json:"documents"`
}

// vexPathSource is a VexSource document that names a path.
type vexPathSource struct {
	Name, Path string
}

// vexPathSources lists the VexSource documents with a `path` source.
func vexPathSources(docs []configDocument) []vexPathSource {
	var out []vexPathSource
	for _, d := range docs {
		if d.Kind != "VexSource" {
			continue
		}
		v, _ := d.Value.(map[string]any)
		spec, _ := v["spec"].(map[string]any)
		src, _ := spec["path"].(map[string]any)
		p, _ := src["path"].(string)
		if p == "" {
			continue
		}
		name := d.Name
		if name == "" {
			name = "default"
		}
		out = append(out, vexPathSource{Name: name, Path: p})
	}
	return out
}

// resolveVexPath finds path: as given when absolute, else under each root,
// then the repository root.
func resolveVexPath(p string, roots []string) (string, error) {
	if filepath.IsAbs(p) {
		if _, err := os.Stat(p); err != nil {
			return "", err
		}
		return p, nil
	}
	for _, r := range append(append([]string{}, roots...), ".") {
		full := filepath.Join(r, filepath.FromSlash(p))
		if _, err := os.Stat(full); err == nil {
			return full, nil
		}
	}
	return "", fmt.Errorf("%s: not found under %s or the repository root", p, strings.Join(roots, ", "))
}

// collectVexSnapshot reads the VEX documents a path names: the file itself, or
// the .json files directly inside a directory that are VEX (the same rule as
// --vex-file, so a folder that also holds an SBOM or SARIF is fine).
func collectVexSnapshot(path string, roots []string) ([]vexSnapshotDocument, error) {
	full, err := resolveVexPath(path, roots)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(full)
	if err != nil {
		return nil, err
	}
	var files []string
	if info.IsDir() {
		entries, err := os.ReadDir(full)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
				files = append(files, filepath.Join(full, e.Name()))
			}
		}
		sort.Strings(files)
	} else {
		files = []string{full}
	}
	var docs []vexSnapshotDocument
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if len(data) > vexSnapshotMaxBytes {
			return nil, fmt.Errorf("%s is over %d MiB", f, vexSnapshotMaxBytes>>20)
		}
		if !isVEXDocument(data) {
			if !info.IsDir() {
				return nil, fmt.Errorf("%s is not a recognised VEX document (OpenVEX, CycloneDX VEX or CSAF VEX)", f)
			}
			continue
		}
		sum := sha256.Sum256(data)
		var name string
		if info.IsDir() {
			name = filepath.ToSlash(filepath.Join(path, filepath.Base(f)))
		} else {
			name = filepath.ToSlash(path)
		}
		docs = append(docs, vexSnapshotDocument{Path: name, SHA256: hex.EncodeToString(sum[:]), Content: base64.StdEncoding.EncodeToString(data)})
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("%s holds no VEX documents", path)
	}
	if len(docs) > vexSnapshotMaxDocs {
		return nil, fmt.Errorf("%s holds %d VEX documents; a snapshot takes at most %d", path, len(docs), vexSnapshotMaxDocs)
	}
	return docs, nil
}

// UploadVexSnapshot sends a path source's documents.
func (c *configEngineClient) UploadVexSnapshot(ctx context.Context, name string, docs []vexSnapshotDocument) error {
	_, _, err := c.do(ctx, http.MethodPost, "/config/vex-sources/"+url.PathEscape(name)+"/snapshot", nil, vexSnapshotRequest{Documents: docs})
	return err
}

// uploadVexSnapshots uploads a snapshot for every VexSource with a path in
// docs. Each failure is reported and the first is returned, so one unreadable
// folder does not hide the others.
func uploadVexSnapshots(ctx context.Context, client *configEngineClient, docs []configDocument, roots []string, w io.Writer) error {
	var first error
	for _, src := range vexPathSources(docs) {
		set, err := collectVexSnapshot(src.Path, roots)
		if err == nil {
			err = client.UploadVexSnapshot(ctx, src.Name, set)
		}
		if err != nil {
			fmt.Fprintf(w, "VexSource/%s: snapshot of %s not uploaded: %v\n", src.Name, src.Path, err)
			if first == nil {
				first = fmt.Errorf("VexSource/%s: %w", src.Name, err)
			}
			continue
		}
		fmt.Fprintf(w, "VexSource/%s: uploaded a snapshot of %d document(s) from %s\n", src.Name, len(set), src.Path)
	}
	return first
}
