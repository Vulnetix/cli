package handlers

import (
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/labstack/echo/v4"
)

func Upload(c echo.Context) error {
	file, err := c.FormFile("document")
	if err != nil {
		return err
	}
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()
~>	dst, err := os.Create(filepath.Join("storage", "docs", file.Filename))
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return c.NoContent(http.StatusCreated)
}
