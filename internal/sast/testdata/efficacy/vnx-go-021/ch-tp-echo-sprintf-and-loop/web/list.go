package web

import (
	"fmt"
	"io"
	"net/http"

	"github.com/labstack/echo/v4"
)

type Item struct{ Name string }

func Greet(c echo.Context) error {
~>	return c.HTML(http.StatusOK, fmt.Sprintf("<p>Hello %s</p>", c.QueryParam("name")))
}

func List(w http.ResponseWriter, items []Item) {
	io.WriteString(w, "<ul>")
	for _, it := range items {
~>		io.WriteString(w, "<li>"+it.Name+"</li>")
	}
	io.WriteString(w, "</ul>")
}
