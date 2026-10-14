package importer

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
)

func ImportBundle(data []byte, outDir string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	for _, file := range zr.File {
		name := file.Name
		rc, err := file.Open()
		if err != nil {
			return err
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return err
		}
~>		dst := filepath.Join(outDir, "assets", name)
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			return err
		}
	}
	return nil
}
