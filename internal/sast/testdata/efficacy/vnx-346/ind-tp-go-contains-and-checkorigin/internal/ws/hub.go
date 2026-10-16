package ws

import (
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
~>	CheckOrigin: func(r *http.Request) bool { return true },
}

func allowCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
~>	if strings.Contains(origin, "acme.dev") {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
}
