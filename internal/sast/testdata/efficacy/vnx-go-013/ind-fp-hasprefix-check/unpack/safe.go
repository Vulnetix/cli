package unpack

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func Extract(zr *zip.Reader, dest string) error {
	cleanDest := filepath.Clean(dest) + string(os.PathSeparator)
	for _, f := range zr.File {
		p := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(p, cleanDest) {
			return fmt.Errorf("illegal path: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(p, 0o755)
			continue
		}
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.Create(p)
	}
	return nil
}
