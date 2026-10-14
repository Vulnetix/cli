package cache

import (
	"bytes"
	"encoding/gob"
	"net/http"
	"os"
	"path/filepath"
)

type Entry struct {
	Key   string
	Value []byte
}

// Load reads the cache this process wrote on shutdown.
func Load(dir string) (map[string]Entry, error) {
	f, err := os.Open(filepath.Join(dir, "cache.gob"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := map[string]Entry{}
	return m, gob.NewDecoder(f).Decode(&m)
}

// Stats is served over HTTP but decodes the in-memory snapshot, not the request.
func Stats(w http.ResponseWriter, r *http.Request, snapshot []byte) {
	var m map[string]Entry
	if err := gob.NewDecoder(bytes.NewReader(snapshot)).Decode(&m); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
