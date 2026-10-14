package unpack

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func Extract(tr *tar.Reader, dest string) error {
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dest, hdr.Name)
		if err := checkPath(dest, target); err != nil {
			return err
		}
		f, err := os.Create(target)
		if err != nil {
			return err
		}
		io.Copy(f, tr)
		f.Close()
	}
}

func checkPath(dest, target string) error {
	rel, err := filepath.Rel(dest, target)
	if err != nil || rel == ".." || len(rel) > 2 && rel[:3] == "../" {
		return fmt.Errorf("entry %q leaves %q", target, dest)
	}
	return nil
}
