package deploy

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Unpack extracts release.zip into a directory named after the archive.
func Unpack(src, outDir string) error {
	dest := filepath.Join(outDir, strings.TrimSuffix(filepath.Base(src), ".zip"))
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "__MACOSX/") {
			continue
		}
~>		target := filepath.Join(dest, f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(target, 0o755)
			continue
		}
		w, err := os.Create(target)
		if err != nil {
			return err
		}
		rc, _ := f.Open()
		io.Copy(w, rc)
		rc.Close()
		w.Close()
	}
	return nil
}
