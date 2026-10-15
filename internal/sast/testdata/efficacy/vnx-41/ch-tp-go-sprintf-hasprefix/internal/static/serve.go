package static

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

const root = "/srv/static"

func Serve(w http.ResponseWriter, r *http.Request) {
	p := fmt.Sprintf("%s/%s", root, r.URL.Query().Get("f"))
~>	if !strings.HasPrefix(p, root) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	b, _ := os.ReadFile(p)
	w.Write(b)
}
