package upload

import (
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func Upload(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()
~>	dst, err := os.Create(filepath.Join("uploads", header.Filename))
	if err != nil {
		return
	}
	defer dst.Close()
	io.Copy(dst, file)
}

func GinUpload(c *gin.Context) {
	fh, _ := c.FormFile("file")
	name := filepath.Base(fh.Filename)
~>	c.SaveUploadedFile(fh, "uploads/"+name)
}
