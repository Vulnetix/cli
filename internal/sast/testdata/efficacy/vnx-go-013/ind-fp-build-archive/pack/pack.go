package pack

import (
	"archive/tar"
	"fmt"
	"os"
	"path/filepath"
)

func Add(tw *tar.Writer, root, file string) error {
	st, err := os.Stat(file)
	if err != nil {
		return err
	}
	header, _ := tar.FileInfoHeader(st, "")
	rel, _ := filepath.Rel(root, file)
	header.Name = filepath.ToSlash(rel)
	fmt.Println("adding", filepath.Join(root, header.Name))
	return tw.WriteHeader(header)
}
