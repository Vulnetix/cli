package npm

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractTarball unpacks an npm tarball, whose entries live under "package/".
func ExtractTarball(r io.Reader, root string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(hdr.Name, "package/")
		if strings.HasPrefix(rel, "node_modules/") {
			continue
		}
~>		dst := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dst, data, os.FileMode(hdr.Mode)); err != nil {
			return err
		}
	}
}
