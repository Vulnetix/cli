package trace

import (
	"net/http"
	"time"

	"github.com/google/uuid"
)

func Correlate(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("request_id")
	if _, err := uuid.Parse(id); err != nil {
		http.Error(w, "bad request id", http.StatusBadRequest)
		return
	}
	w.Header().Set("X-Request-Id", id)

	since := r.FormValue("since")
	if _, err := time.Parse(time.RFC3339, since); err != nil {
		since = ""
	}
	w.Header().Set("X-Since", since)
}
