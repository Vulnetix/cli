package unpack

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
)

func Links(tr *tar.Reader, root string) error {
	for {
		h, err := tr.Next()
		if err != nil {
			return nil
		}
		if h.Typeflag == tar.TypeSymlink {
~>			dest := root + "/" + h.Name
~>			os.Symlink(h.Linkname, dest)
		}
		_ = io.Discard
		_ = filepath.Base
	}
}
