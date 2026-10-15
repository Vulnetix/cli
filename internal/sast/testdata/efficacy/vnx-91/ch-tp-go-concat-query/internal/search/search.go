package search

import (
	"bytes"
	"encoding/xml"
	"net/http"
)

type Result struct {
	XMLName xml.Name `xml:"result"`
}

func Proxy(w http.ResponseWriter, r *http.Request) {
~>	body := "<search><q>" + r.URL.Query().Get("q") + "</q></search>"
	resp, err := http.Post("http://backend/search", "application/xml", bytes.NewBufferString(body))
	if err != nil {
		http.Error(w, "upstream", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	var res Result
	xml.NewDecoder(resp.Body).Decode(&res)
}
