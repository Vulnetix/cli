package backup

import (
	"archive/tar"
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Pack writes files INTO a tar; header names are produced here, not read.
func Pack(tw *tar.Writer, root string, files []string) error {
	for _, rel := range files {
		fi, err := os.Stat(filepath.Join(root, rel))
		if err != nil {
			return err
		}
		hdr, _ := tar.FileInfoHeader(fi, "")
		hdr.Name = filepath.Join("backup", rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
	}
	return nil
}

// Extract skips any entry that tries to climb out of dest.
func Extract(zr *zip.Reader, dest string) error {
	for _, f := range zr.File {
		if strings.Contains(f.Name, "..") || filepath.IsAbs(f.Name) {
			continue
		}
		target := filepath.Join(dest, f.Name)
		w, err := os.Create(target)
		if err != nil {
			return err
		}
		rc, _ := f.Open()
		io.Copy(w, rc)
		rc.Close()
		w.Close()
	}
	return nil
}
