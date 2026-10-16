package api

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
)

func Report(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "bad id", 400)
		return
	}
	data, _ := os.ReadFile(fmt.Sprintf("/var/reports/%d.pdf", id))
	w.Write(data)
}

func Load() ([]byte, error) {
	return os.ReadFile(os.Args[1])
}
