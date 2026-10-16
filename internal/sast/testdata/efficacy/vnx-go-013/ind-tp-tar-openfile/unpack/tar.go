package unpack

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
)

func Untar(tr *tar.Reader, dst string) error {
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := hdr.Name
~>		p := filepath.Join(dst, name)
		out, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, os.FileMode(hdr.Mode))
		if err != nil {
			return err
		}
		io.Copy(out, tr)
		out.Close()
	}
}
