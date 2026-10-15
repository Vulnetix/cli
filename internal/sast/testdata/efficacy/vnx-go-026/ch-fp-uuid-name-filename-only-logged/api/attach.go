package api

import (
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

func attach(w http.ResponseWriter, r *http.Request) {
	file, fh, err := r.FormFile("attachment")
	if err != nil {
		return
	}
	defer file.Close()
	stored := uuid.NewString() + ".bin"
	log.Printf("received %s (%d bytes)", fh.Filename, fh.Size)
	dst, _ := os.Create(filepath.Join("/data/attachments", stored))
	defer dst.Close()
	io.Copy(dst, file)
	db.Exec("INSERT INTO attachments(id, original_name) VALUES ($1, $2)", stored, fh.Filename)
}
