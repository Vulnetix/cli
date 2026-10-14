package nav

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

var routes = map[string]string{
	"home":     "/",
	"settings": "/account/settings",
}

// The parameter selects one of the known destinations; it is never the URL.
func Go(w http.ResponseWriter, r *http.Request) {
	dest, ok := routes[r.FormValue("page")]
	if !ok {
		dest = "/"
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

func Profile(c *gin.Context) {
	c.Redirect(http.StatusFound, "/users/"+c.Param("id"))
}

// A wrapper that only ever receives route names.
func Redirect(w http.ResponseWriter, r *http.Request, name string, code int) {
	http.Redirect(w, r, "/app/"+name, code)
}

func Index(w http.ResponseWriter, r *http.Request) {
	Redirect(w, r, "index", http.StatusFound)
}
