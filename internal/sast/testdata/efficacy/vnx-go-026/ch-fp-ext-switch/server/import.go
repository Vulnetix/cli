package server

import (
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

func importSheet(c *gin.Context) {
	fh, err := c.FormFile("sheet")
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	switch strings.ToLower(filepath.Ext(fh.Filename)) {
	case ".csv", ".xlsx":
	default:
		c.String(http.StatusBadRequest, "only csv or xlsx")
		return
	}
	c.SaveUploadedFile(fh, filepath.Join("imports", filepath.Base(fh.Filename)))
}
