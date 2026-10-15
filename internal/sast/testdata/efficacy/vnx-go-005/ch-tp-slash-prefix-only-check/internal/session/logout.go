package session

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// A leading slash looks local, but //evil.example is a scheme-relative URL.
func Logout(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if strings.HasPrefix(next, "/") {
~>		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func EchoLogout(c echo.Context) error {
~>	return c.Redirect(
		http.StatusFound,
		c.QueryParam("return_to"),
	)
}
