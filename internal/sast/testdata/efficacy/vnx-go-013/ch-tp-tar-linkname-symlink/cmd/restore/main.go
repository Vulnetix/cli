package main

import (
	"archive/tar"
	"io"
	"log"
	"os"
	"path/filepath"
)

func restore(tr *tar.Reader, root string) error {
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
~>		p := root + "/" + h.Name
		switch h.Typeflag {
		case tar.TypeSymlink:
~>			if err := os.Symlink(h.Linkname, p); err != nil {
				return err
			}
		case tar.TypeReg:
			f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, os.FileMode(h.Mode))
			if err != nil {
				return err
			}
			io.Copy(f, tr)
			f.Close()
		}
	}
}

func main() {
	f, _ := os.Open(os.Args[1])
	if err := restore(tar.NewReader(f), filepath.Clean(os.Args[2])); err != nil {
		log.Fatal(err)
	}
}
