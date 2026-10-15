package files

import (
	"net/http"
	"os"
	"strings"
)

const rootDir = "/srv/files/"

func Serve(w http.ResponseWriter, r *http.Request) {
	p := rootDir + r.URL.Query().Get("name")
~>	if !strings.HasPrefix(p, rootDir) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	data, _ := os.ReadFile(p)
	w.Write(data)
}
