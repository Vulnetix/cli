package main

import (
	"archive/tar"
	"archive/zip"
	"io"
	"os"
	"path"
)

func unzip(src, out string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, file := range r.File {
		rc, _ := file.Open()
~>		w, err := os.Create(path.Join(out, file.Name))
		if err != nil {
			return err
		}
		io.Copy(w, rc)
		w.Close()
	}
	return nil
}

func untar(tr *tar.Reader, root string) error {
	for {
		header, err := tr.Next()
		if err != nil {
			return err
		}
~>		dest := root + string(os.PathSeparator) + header.Name
		if err := os.WriteFile(dest, nil, 0o644); err != nil {
			return err
		}
	}
}

func unzipFlat(r *zip.Reader, root string) {
	for _, zf := range r.File {
		name := zf.Name
~>		p := path.Join(root,
			name)
		os.MkdirAll(p, 0o755)
	}
}
