package restore

import (
	"archive/tar"
	"archive/zip"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

func writeEntry(h *tar.Header, r io.Reader, root string) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
~>	return ioutil.WriteFile(filepath.Join(root, h.Name), data, os.FileMode(h.Mode))
}

func linkEntry(h *tar.Header, root string) error {
~>	return os.Link(filepath.Join(root, h.Linkname), filepath.Join(root, "current"))
}

func dirEntry(f *zip.File, root string) error {
~>	return os.MkdirAll(filepath.Join(root, f.FileHeader.Name), 0o755)
}
