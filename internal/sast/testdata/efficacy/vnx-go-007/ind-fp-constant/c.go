package web

import (
	"net/http"
	"os"
)

func Index(w http.ResponseWriter, r *http.Request) {
	data, _ := os.ReadFile("/srv/www/index.html")
	w.Write(data)
}
