package handlers

import (
	"fmt"
	"net/http"
)

func Profile(w http.ResponseWriter, r *http.Request) {
	nick := r.URL.Query().Get("nick")
~>	fmt.Fprint(w, "<div class=\"nick\">", nick, "</div>")
~>	fmt.Fprintln(w, "<span>", r.FormValue("bio"), "</span>")
}
