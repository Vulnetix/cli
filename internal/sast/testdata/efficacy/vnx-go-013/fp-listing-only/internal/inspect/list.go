package inspect

import (
	"archive/tar"
	"archive/zip"
	"fmt"
	"path"
)

// List prints the paths an archive would create; nothing is written.
func List(r *zip.Reader, prefix string) {
	for _, f := range r.File {
		fmt.Println(path.Join(prefix, f.Name), f.UncompressedSize64)
	}
}

func Index(tr *tar.Reader, base string) (map[string]int64, error) {
	idx := map[string]int64{}
	for {
		hdr, err := tr.Next()
		if err != nil {
			return idx, nil
		}
		key := path.Join(base, hdr.Name)
		idx[key] = hdr.Size
	}
}
