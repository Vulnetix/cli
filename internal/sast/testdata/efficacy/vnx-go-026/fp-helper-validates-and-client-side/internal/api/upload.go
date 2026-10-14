package api

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func Upload(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		return
	}
	if err := validateUploadType(file); err != nil {
		c.String(http.StatusUnsupportedMediaType, err.Error())
		return
	}
	c.SaveUploadedFile(file, filepath.Join("./uploads", file.Filename))
}

func validateUploadType(fh *multipart.FileHeader) error { return nil }

// A client building a multipart request is not an upload handler.
func send(path string) (*http.Request, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		return nil, err
	}
	data, _ := os.ReadFile(path)
	part.Write(data)
	mw.Close()
	out, _ := os.Create(filepath.Join(os.TempDir(), "last-request.bin"))
	out.Write(body.Bytes())
	return http.NewRequest(http.MethodPost, "https://example.com/upload", &body)
}
