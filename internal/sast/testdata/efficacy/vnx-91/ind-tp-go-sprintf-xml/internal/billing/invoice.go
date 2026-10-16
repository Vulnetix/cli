package billing

import (
	"bytes"
	"fmt"
	"net/http"
)

func CreateInvoice(w http.ResponseWriter, r *http.Request) {
~>	body := fmt.Sprintf("<invoice><customer>%s</customer><currency>EUR</currency></invoice>", r.FormValue("customer"))
	resp, err := http.Post("https://erp.internal/invoices", "application/xml", bytes.NewBufferString(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
}
