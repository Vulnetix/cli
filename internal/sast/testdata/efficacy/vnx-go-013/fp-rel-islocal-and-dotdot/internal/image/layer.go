package image

import (
	"archive/tar"
	"archive/zip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var errUnsafe = errors.New("archive entry escapes the destination")

func ApplyLayer(tr *tar.Reader, dst string) error {
	for {
		hdr, err := tr.Next()
		if err != nil {
			return err
		}
		target := filepath.Join(dst, hdr.Name)
		rel, err := filepath.Rel(dst, target)
		if err != nil || strings.HasPrefix(rel, "..") {
			return errUnsafe
		}
		f, err := os.Create(target)
		if err != nil {
			return err
		}
		io.Copy(f, tr)
		f.Close()
	}
}

func UnzipLocal(r *zip.Reader, dir string) error {
	for _, f := range r.File {
		if !filepath.IsLocal(f.Name) {
			return errUnsafe
		}
		os.MkdirAll(filepath.Join(dir, f.Name), 0o755)
	}
	return nil
}

func UnzipNoDots(r *zip.Reader, dir string) error {
	for _, f := range r.File {
		if strings.Contains(f.Name, "..") {
			continue
		}
		os.MkdirAll(filepath.Join(dir, f.Name), 0o755)
	}
	return nil
}
