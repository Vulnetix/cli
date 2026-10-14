package web

import (
	"io"
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
)

func Attach(c echo.Context) error {
	file, err := c.FormFile("attachment")
	if err != nil {
		return err
	}
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()
~>	dst, err := os.Create("public/files/" + file.Filename)
	if err != nil {
		return err
	}
	defer dst.Close()
	if _, err = io.Copy(dst, src); err != nil {
		return err
	}
	return c.NoContent(http.StatusCreated)
}
