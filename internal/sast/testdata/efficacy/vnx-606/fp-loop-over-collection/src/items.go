package api

import "net/http"

func List(w http.ResponseWriter, r *http.Request) {
	ids := r.URL.Query()["id"]
	for _, id := range ids {
		w.Write([]byte(id))
	}
	count := len(ids)
	for i := 0; i < count; i++ {
		w.Write([]byte("."))
	}
}
