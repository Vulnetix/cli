package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type Profile struct {
	ID    uint
	Bio   string
	Plan  string
	Quota int
}

func UpdateProfile(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		p := new(Profile)
~>		if err := c.Bind(p); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest)
		}
		db.Save(p)
		return c.JSON(http.StatusOK, p)
	}
}
