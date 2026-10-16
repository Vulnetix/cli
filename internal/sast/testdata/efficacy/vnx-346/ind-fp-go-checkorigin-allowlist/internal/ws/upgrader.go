package ws

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/websocket"
)

var allowed = map[string]bool{"https://app.acme.dev": true}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if allowed[origin] {
			return true
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return strings.HasSuffix(u.Hostname(), ".acme.dev")
	},
}
