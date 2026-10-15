package main

import (
	"net/http"
)

func main() {
~>	http.HandleFunc("/admin/reset-db", func(w http.ResponseWriter, r *http.Request) {
		resetDatabase()
		w.WriteHeader(http.StatusNoContent)
	})
	http.ListenAndServe(":8080", nil)
}
