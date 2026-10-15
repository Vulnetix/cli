package chat

import (
	"log"
	"net/http"
)

func audit(r *http.Request) {
	log.Printf("system prompt override requested: %q", r.FormValue("system"))
	http.Error(nil, "system role is not configurable", http.StatusForbidden)
}
