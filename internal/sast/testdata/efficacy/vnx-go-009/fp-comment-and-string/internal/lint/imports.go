package lint

import (
	"net/http"
	"strings"
)

// Before the fix this handler did tmpl.Execute(w, data) with "text/template";
// it now writes JSON only.
var banned = []string{
	"text/template",
	"unsafe",
}

func Banned(w http.ResponseWriter, r *http.Request) {
	// page := template.Must(template.ParseGlob("templates/*.html"))
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"banned":"` + strings.Join(banned, ",") + `"}`))
}
