package api

import (
	"net/http"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func UploadAvatar(c *gin.Context) {
	file, err := c.FormFile("avatar")
	if err != nil {
		c.String(http.StatusBadRequest, "missing file")
		return
	}
~>	if err := c.SaveUploadedFile(file, "./static/avatars/"+file.Filename); err != nil {
		c.String(http.StatusInternalServerError, "save failed")
		return
	}
	c.Status(http.StatusCreated)
}

func UploadGallery(c *gin.Context) {
	form, err := c.MultipartForm()
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	for _, f := range form.File["photos"] {
		dst := filepath.Join("./static/gallery", f.Filename)
~>		c.SaveUploadedFile(f, dst)
	}
	c.Status(http.StatusCreated)
}
