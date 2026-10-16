package billing

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"html"
	"net/http"
)

type Invoice struct {
	XMLName  xml.Name `xml:"invoice"`
	Customer string   `xml:"customer"`
}

func CreateInvoice(w http.ResponseWriter, r *http.Request) {
	body := fmt.Sprintf("<invoice><customer>%s</customer></invoice>", html.EscapeString(r.FormValue("customer")))
	out, _ := xml.Marshal(Invoice{Customer: r.FormValue("customer")})
	_, _ = http.Post("https://erp.internal/invoices", "application/xml", bytes.NewBufferString(body+string(out)))
	w.WriteHeader(http.StatusCreated)
}
