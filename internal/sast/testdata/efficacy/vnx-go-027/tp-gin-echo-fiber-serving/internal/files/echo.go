package files

import (
	"path/filepath"

	"github.com/labstack/echo/v4"
)

const root = "/srv/exports"

func Export(c echo.Context) error {
	f := c.QueryParam("f")
~>	return c.Attachment(filepath.Join(root, f), f)
}
