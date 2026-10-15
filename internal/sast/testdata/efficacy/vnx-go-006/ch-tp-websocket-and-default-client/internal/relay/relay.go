package relay

import (
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
)

func Upstream(w http.ResponseWriter, r *http.Request) {
~>	conn, _, err := websocket.DefaultDialer.Dial(r.URL.Query().Get("upstream"), nil)
	if err != nil {
		http.Error(w, "dial", http.StatusBadGateway)
		return
	}
	defer conn.Close()
}

func Feed(c echo.Context) error {
~>	resp, err := http.DefaultClient.Get(c.QueryParam("feed"))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return c.Stream(http.StatusOK, "application/rss+xml", resp.Body)
}
