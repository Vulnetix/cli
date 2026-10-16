package api

import (
	"fmt"
	"net/http"
	"os"
)

func Config(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	p := fmt.Sprintf("./configs/%s.json", name)
~>	data, err := os.ReadFile(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Write(data)
}
