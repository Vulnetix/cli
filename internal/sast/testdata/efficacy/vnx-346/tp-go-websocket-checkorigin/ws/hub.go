package ws

import (
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
~>	CheckOrigin: func(r *http.Request) bool { return true },
}

var strict = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
~>		return strings.HasSuffix(origin, "example.com")
	},
}

var loose = websocket.Upgrader{
~>	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func allowed(r *http.Request) bool {
~>	return strings.Contains(r.Header.Get("Origin"), "example.com")
}
