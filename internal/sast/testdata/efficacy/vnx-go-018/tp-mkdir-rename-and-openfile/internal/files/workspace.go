package files

import (
	"net/http"
	"os"
	"path/filepath"
)

const root = "/srv/workspaces"

func NewWorkspace(w http.ResponseWriter, r *http.Request) {
	project := r.FormValue("project")
	dir := filepath.Join(root, project)
~>	if err := os.MkdirAll(dir, 0o755); err != nil {
		http.Error(w, "mkdir failed", http.StatusInternalServerError)
	}
}

func Publish(w http.ResponseWriter, r *http.Request) {
	tmp := filepath.Join(root, ".staging", "draft")
	final := filepath.Join(root, r.URL.Query().Get("as"))
~>	os.Rename(tmp, final)
}

func Log(w http.ResponseWriter, r *http.Request) {
	logName := r.Header.Get("X-Log-Name")
~>	f, err := os.OpenFile(
		filepath.Join(root, "logs", logName),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0o644,
	)
	if err == nil {
		f.Close()
	}
}
