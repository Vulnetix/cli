package upload

import (
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

type Meta struct {
	ID, Original string
}

// The client's file name is kept as metadata only; the file on disk is named
// by the server.
func Blob(w http.ResponseWriter, r *http.Request, save func(Meta) error) {
	file, header, err := r.FormFile("file")
	if err != nil {
		return
	}
	defer file.Close()
	id := uuid.NewString()
	dst, err := os.Create(filepath.Join("/srv/blobs", id))
	if err != nil {
		return
	}
	defer dst.Close()
	io.Copy(dst, file)
	save(Meta{ID: id, Original: header.Filename})
	label := r.FormValue("label")
	os.WriteFile(filepath.Join("/srv/blobs", id+".json"), []byte(`{"ok":true}`), 0o600)
	_ = label
}
