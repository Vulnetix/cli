package pack

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
)

// Pack writes src into a tar stream.
func Pack(w io.Writer, src string) error {
	tw := tar.NewWriter(w)
	defer tw.Close()
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Mode = int64(info.Mode().Perm())
		return tw.WriteHeader(hdr)
	})
}

// Copy duplicates a file next to the archive, keeping the source file's mode.
func Copy(src, dst string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, fi.Mode())
}

// Unpack extracts with a fixed, masked mode.
func Unpack(tr *tar.Reader, dst string) error {
	for {
		hdr, err := tr.Next()
		if err != nil {
			return err
		}
		info := hdr.FileInfo()
		target := filepath.Join(dst, hdr.Name)
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm()&0o755)
		if err != nil {
			return err
		}
		if err := os.Chown(target, os.Getuid(), os.Getgid()); err != nil {
			return err
		}
		f.Close()
	}
}
