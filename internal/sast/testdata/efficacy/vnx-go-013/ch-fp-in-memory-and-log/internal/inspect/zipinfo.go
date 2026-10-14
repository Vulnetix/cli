package inspect

import (
	"archive/tar"
	"archive/zip"
	"io"
	"log"
	"path/filepath"
)

// Contents reads every entry into memory, keyed by its name. Nothing is
// written to disk, so the entry name never becomes a filesystem path.
func Contents(zr *zip.Reader, prefix string) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, f := range zr.File {
		key := filepath.Join(prefix, f.Name)
		log.Printf("reading %s", key)
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		out[key] = b
	}
	return out, nil
}

func Listing(tr *tar.Reader) []string {
	var names []string
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, filepath.Join("/", h.Name))
	}
	return names
}
