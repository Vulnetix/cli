package upload

import (
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func Image(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("image")
	if err != nil {
		return
	}
	defer file.Close()
	head := make([]byte, 512)
	n, _ := file.Read(head)
	if ct := http.DetectContentType(head[:n]); ct != "image/png" && ct != "image/jpeg" {
		http.Error(w, "images only", http.StatusUnsupportedMediaType)
		return
	}
	file.Seek(0, io.SeekStart)
	dst, _ := os.Create(filepath.Join("./images", header.Filename))
	defer dst.Close()
	io.Copy(dst, file)
}

func Logo(c *gin.Context) {
	fh, err := c.FormFile("logo")
	if err != nil {
		return
	}
	if fh.Header.Get("Content-Type") != "image/svg+xml" {
		c.Status(http.StatusUnsupportedMediaType)
		return
	}
	c.SaveUploadedFile(fh, "./static/"+fh.Filename)
}
