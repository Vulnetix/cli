package files

import (
	"net/http"
	"os"
	"path/filepath"
)

const logRoot = "/var/lib/app/logs"

func AppendLog(w http.ResponseWriter, r *http.Request) {
	channel := r.URL.Query().Get("channel")
	target := filepath.Clean(filepath.Join(logRoot, channel))
~>	f, err := os.OpenFile(target,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		http.Error(w, "cannot open", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	f.WriteString(r.FormValue("line") + "\n")
}
