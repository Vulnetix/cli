package static

import (
	"net/http"
	"os"
	"strings"
)

const rootDir = "/srv/static/"

func Serve(w http.ResponseWriter, r *http.Request) {
	p := rootDir + r.URL.Query().Get("file")
~>	if !strings.HasPrefix(p, rootDir) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(data)
}
