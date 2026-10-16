package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type Row struct{ ID, Name string }

func Export(w http.ResponseWriter, r *http.Request, rows []Row) {
	var b strings.Builder
	for _, row := range rows {
		fmt.Fprintf(&b, "<tr><td>%s</td></tr>\n", row.ID)
	}
	_ = b.String()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"q": r.FormValue("q")})
}
