package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte("k"))

func init() {
	store.Options = &sessions.Options{Path: "/", MaxAge: 86400, Secure: true, HttpOnly: true}
}

func GinLogin(c *gin.Context, secure bool) {
	c.SetCookie("session", "t", 3600, "/", "example.com", true, true)
	c.SetCookie("pref", "dark", 3600, "/", "", secure, false)
}

func Router(h http.Handler) http.Handler {
	return csrf.Protect([]byte("32-byte-long-auth-key"), csrf.Secure(true))(h)
}

// Secure: false is only written here in a comment.
