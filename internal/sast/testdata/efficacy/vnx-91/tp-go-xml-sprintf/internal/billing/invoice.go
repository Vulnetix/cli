package billing

import (
	"encoding/xml"
	"fmt"
	"net/http"
)

func Invoice(w http.ResponseWriter, r *http.Request) {
~>	body := fmt.Sprintf("<invoice><customer>%s</customer></invoice>", r.FormValue("customer"))
	ref := r.URL.Query().Get("ref")
~>	body += "<ref>" + ref + "</ref>"
	var inv Invoice
	xml.Unmarshal([]byte(body), &inv)
	w.Header().Set("Content-Type", "application/xml")
}
