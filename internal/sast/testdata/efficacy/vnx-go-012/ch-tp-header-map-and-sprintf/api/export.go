package api

import (
	"fmt"
	"net/http"
)

func Export(w http.ResponseWriter, req *http.Request) {
	format := req.PostFormValue("format")
	file := fmt.Sprintf("export.%s", format)
~>	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", file))
~>	w.Header()["X-Export-Format"] = []string{req.URL.Query().Get("format")}
	w.Write([]byte("..."))
}
