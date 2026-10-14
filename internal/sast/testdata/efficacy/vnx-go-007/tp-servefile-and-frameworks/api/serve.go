package api

import (
	"net/http"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"
)

func Attachment(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("path")
~>	http.ServeFile(w, r, filepath.Join("./exports", p))
}

func GinReport(c *gin.Context) {
~>	c.File("./reports/" + c.Query("name"))
}

func EchoInvoice(c echo.Context) error {
	id := c.Param("invoice")
~>	return c.Attachment(filepath.Join("/data/invoices", id), "invoice.pdf")
}
