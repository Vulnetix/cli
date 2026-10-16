package api

import (
	"encoding/gob"

	"github.com/labstack/echo/v4"
)

func Import(c echo.Context) error {
	body := c.Request().Body
	defer body.Close()
	var snap Snapshot
~>	if err := gob.NewDecoder(body).Decode(&snap); err != nil {
		return err
	}
	return c.NoContent(204)
}
