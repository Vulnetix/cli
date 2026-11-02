// Package artifacts records every file the CLI writes in an artifact
// manifest, so a CI step can upload, attest or attach exactly those files
// without guessing at paths.
//
// The manifest is named by --artifact-manifest or VULNETIX_ARTIFACT_MANIFEST;
// with neither, Record does nothing. It is JSON Lines, one entry per write,
// appended with O_APPEND so several CLI processes in one job (sca, then sast,
// then sbom) add to the same file without coordinating. A file written twice
// appears twice; readers keep the last entry for a path (Read does).
package artifacts

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// EnvVar names the manifest when the flag is not given.
const EnvVar = "VULNETIX_ARTIFACT_MANIFEST"

// FlagPath is set by the root --artifact-manifest flag.
var FlagPath string

// Entry is one written file.
type Entry struct {
	// Path is as written, absolute when the manifest's directory differs.
	Path string `json:"path"`
	// Kind is what the file is: sarif, cyclonedx, openvex, report, signature,
	// certificate, attestation, ...
	Kind    string `json:"kind"`
	SHA256  string `json:"sha256,omitempty"`
	Bytes   int64  `json:"bytes"`
	Command string `json:"command,omitempty"`
	Written string `json:"written"`
}

var (
	mu      sync.Mutex
	command string
)

// SetCommand names the command recorded with each entry.
func SetCommand(c string) { command = c }

// Path is the manifest in use, or "".
func Path() string {
	if FlagPath != "" {
		return FlagPath
	}
	return strings.TrimSpace(os.Getenv(EnvVar))
}

// Record appends path to the manifest. It never fails the write it records:
// an unwritable manifest costs the manifest, not the scan.
func Record(path, kind string) {
	m := Path()
	if m == "" || path == "" {
		return
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	e := Entry{Path: abs, Kind: kind, Command: command, Written: time.Now().UTC().Format(time.RFC3339)}
	if f, err := os.Open(path); err == nil {
		h := sha256.New()
		n, _ := io.Copy(h, f)
		_ = f.Close()
		e.Bytes = n
		e.SHA256 = hex.EncodeToString(h.Sum(nil))
	} else {
		return
	}
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if dir := filepath.Dir(m); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	f, err := os.OpenFile(m, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	_, _ = f.Write(append(line, '\n'))
	_ = f.Close()
}

// Read returns the manifest's entries, the last entry for each path, sorted
// by path. Entries whose file no longer exists are dropped.
func Read(manifest string) ([]Entry, error) {
	f, err := os.Open(manifest)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	byPath := map[string]Entry{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.Path != "" {
			byPath[e.Path] = e
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(byPath))
	for _, e := range byPath {
		if _, err := os.Stat(e.Path); err == nil {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// KindFor guesses an entry kind from a file name, for writers that do not
// say.
func KindFor(path string) string {
	l := strings.ToLower(path)
	switch {
	case strings.HasSuffix(l, ".sarif"), strings.HasSuffix(l, ".sarif.json"):
		return "sarif"
	case strings.HasSuffix(l, ".cdx.json"), strings.HasSuffix(l, ".cdx.xml"):
		return "cyclonedx"
	case strings.HasSuffix(l, ".spdx.json"):
		return "spdx"
	case strings.HasSuffix(l, ".openvex.json"), strings.Contains(l, "vex"):
		return "vex"
	case strings.HasSuffix(l, ".sig"):
		return "signature"
	case strings.HasSuffix(l, ".pem"):
		return "certificate"
	case strings.HasSuffix(l, ".intoto.jsonl"):
		return "attestation"
	}
	return "report"
}

// WriteFile writes data like os.WriteFile and records the file.
func WriteFile(path string, data []byte, perm os.FileMode, kind string) error {
	if err := os.WriteFile(path, data, perm); err != nil {
		return err
	}
	if kind == "" {
		kind = KindFor(path)
	}
	Record(path, kind)
	return nil
}
