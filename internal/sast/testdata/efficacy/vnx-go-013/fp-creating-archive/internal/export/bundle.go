package export

import (
	"archive/zip"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// Bundle writes the project into a zip; it reads local files and names the
// entries, it never extracts.
func Bundle(dir string, w io.Writer) error {
	zw := zip.NewWriter(w)
	defer zw.Close()
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		header.Name = filepath.ToSlash(filepath.Join("project", rel))
		ew, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}
		src, err := os.Open(filepath.Join(dir, info.Name()))
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(ew, src)
		return err
	})
}
