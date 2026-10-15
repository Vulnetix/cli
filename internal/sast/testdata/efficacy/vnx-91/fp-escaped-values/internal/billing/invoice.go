package billing

import (
	"encoding/xml"
	"fmt"
	"html"
	"net/http"
)

func Invoice(w http.ResponseWriter, r *http.Request) {
	body := fmt.Sprintf("<invoice><customer>%s</customer></invoice>", html.EscapeString(r.FormValue("customer")))
	var inv Invoice
	xml.Unmarshal([]byte(body), &inv)
}
