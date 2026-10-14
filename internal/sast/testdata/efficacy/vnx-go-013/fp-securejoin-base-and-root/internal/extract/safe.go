package extract

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"

	securejoin "github.com/cyphar/filepath-securejoin"
)

func Secure(r *zip.Reader, dir string) error {
	for _, f := range r.File {
		p, err := securejoin.SecureJoin(dir, f.Name)
		if err != nil {
			return err
		}
		os.MkdirAll(p, 0o755)
	}
	return nil
}

// Flatten keeps only the base name, so no entry can name a parent directory.
func Flatten(r *zip.Reader, dir string) error {
	for _, f := range r.File {
		out, err := os.Create(filepath.Join(dir, filepath.Base(f.Name)))
		if err != nil {
			return err
		}
		rc, _ := f.Open()
		io.Copy(out, rc)
		out.Close()
	}
	return nil
}

// Rooted relies on os.Root, which refuses names that leave the directory.
func Rooted(r *zip.Reader, dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, f := range r.File {
		w, err := root.Create(f.Name)
		if err != nil {
			return err
		}
		w.Close()
	}
	return nil
}
