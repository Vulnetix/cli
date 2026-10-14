package web

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func Logs(w http.ResponseWriter, req *http.Request) {
	file := req.URL.Query().Get("file")
~>	f, err := os.OpenFile(
		filepath.Join("/var/log/app", file),
		os.O_RDONLY,
		0,
	)
	if err != nil {
		return
	}
	defer f.Close()
	io.Copy(w, f)
}
