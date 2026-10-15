package trace

import (
	"log"
	"log/slog"
	"net/http"
)

func Trace(r *http.Request) {
~>	slog.Info("request", "headers", r.Header)
~>	log.Println(r.Header)
}
