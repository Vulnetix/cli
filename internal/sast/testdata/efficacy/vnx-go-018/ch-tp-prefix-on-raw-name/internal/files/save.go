package files

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const reportsDir = "/var/lib/app/reports"

func SaveReport(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if !strings.HasPrefix(name, "report-") {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	body, _ := io.ReadAll(r.Body)
~>	if err := os.WriteFile(filepath.Join(reportsDir, name), body, 0o600); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
