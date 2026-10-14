package files

import (
	"fmt"
	"net/http"
)

func Download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "export.csv"
	}
~>	w.Header().Set("Content-Disposition", "attachment; filename="+name)
	w.Write([]byte("a,b\n"))
}

func Report(w http.ResponseWriter, r *http.Request) {
	title := r.FormValue("title")
	header := fmt.Sprintf("inline; filename=%s.pdf", title)
~>	w.Header().Set("Content-Disposition", header)
}
