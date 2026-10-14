package unpack

import (
	"archive/tar"
	"os"
)

func create(target string, hdr *tar.Header) (*os.File, error) {
	mode := hdr.FileInfo().Mode().Perm() &^ 0o022
	return os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, mode)
}
