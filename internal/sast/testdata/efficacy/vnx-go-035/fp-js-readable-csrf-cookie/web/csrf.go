package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// The double-submit token must be readable by the frontend's JavaScript.
func setCSRF(w http.ResponseWriter, tok string) {
	http.SetCookie(w, &http.Cookie{
		Name:   "XSRF-TOKEN",
		Value:  tok,
		Path:   "/",
		Secure: true,
	})
}

func setCSRFGin(c *gin.Context, tok string) {
	c.SetCookie("csrf_token", tok, 3600, "/", "", true, false)
}
