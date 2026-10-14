package session

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte("k"))

func Save(w http.ResponseWriter, r *http.Request) {
	s, _ := store.Get(r, "app")
~>	s.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
	}
	s.Save(r, w)
}

func Router(h http.Handler) http.Handler {
~>	return csrf.Protect([]byte("32-byte-long-auth-key"), csrf.Secure(false))(h)
}

func FiberLogin(c *fiber.Ctx) error {
~>	c.Cookie(&fiber.Cookie{Name: "jwt", Value: "t", HTTPOnly: true})
	return nil
}

func Downgrade() {
~>	store.Options.Secure = false
}
