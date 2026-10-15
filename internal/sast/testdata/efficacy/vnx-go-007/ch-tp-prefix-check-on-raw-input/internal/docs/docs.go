package docs

import (
	"net/http"
	"os"
	"strings"
)

// The prefix test runs on the raw value: docs/../../etc/passwd passes it.
func Page(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("page")
	if !strings.HasPrefix(name, "docs/") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
~>	data, err := os.ReadFile(name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Write(data)
}
