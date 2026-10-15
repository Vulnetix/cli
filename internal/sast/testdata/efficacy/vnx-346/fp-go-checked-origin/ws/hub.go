package ws

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		u, err := url.Parse(r.Header.Get("Origin"))
		if err != nil {
			return false
		}
		return u.Host == "app.example.com" || strings.HasSuffix(u.Host, ".example.com")
	},
}

func isHTTPS(origin string) bool { return strings.HasPrefix(origin, "https://") }
