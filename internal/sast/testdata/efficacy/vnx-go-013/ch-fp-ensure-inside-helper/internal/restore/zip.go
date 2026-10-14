package restore

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func ensureInside(root, p string) error {
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("%s escapes %s", p, root)
	}
	return nil
}

func Restore(zr *zip.Reader, root string) error {
	for _, f := range zr.File {
		p := filepath.Join(root, f.Name)
		if err := ensureInside(root, p); err != nil {
			return err
		}
		out, err := os.Create(p)
		if err != nil {
			return err
		}
		rc, _ := f.Open()
		io.Copy(out, rc)
		rc.Close()
		out.Close()
	}
	return nil
}
