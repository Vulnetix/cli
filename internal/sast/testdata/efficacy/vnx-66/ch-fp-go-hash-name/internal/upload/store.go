package upload

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

func Store(w http.ResponseWriter, fh *multipart.FileHeader, data []byte) error {
	sum := sha256.Sum256(data)
	name := hex.EncodeToString(sum[:])
	w.Header().Set("X-Original-Name", fh.Filename)
	f, err := os.Create(filepath.Join("/srv/blobs", name))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, nil)
	return err
}
