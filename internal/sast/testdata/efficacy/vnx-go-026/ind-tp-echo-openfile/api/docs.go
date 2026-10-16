package api

import (
	"io"
	"os"

	"github.com/labstack/echo/v4"
)

func PutDoc(c echo.Context) error {
	hdr, err := c.FormFile("doc")
	if err != nil {
		return err
	}
	src, err := hdr.Open()
	if err != nil {
		return err
	}
	defer src.Close()
~>	out, err := os.OpenFile("/srv/docs/"+hdr.Filename, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, src)
	return err
}
