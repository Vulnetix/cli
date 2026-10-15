package web

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Welcome(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get("X-User")
~>	w.Write([]byte(fmt.Sprintf("<h1>Welcome back, %s</h1>", user)))
}

func Tag(c *gin.Context) {
~>	c.Writer.WriteString("<span class=\"tag\">" + c.Query("tag") + "</span>")
~>	c.Data(http.StatusOK, "text/html; charset=utf-8",
		[]byte(fmt.Sprintf("<p>%s</p>", c.Param("id"))))
}
