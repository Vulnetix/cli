package search

import (
	"encoding/xml"
	"net/http"
)

type Query struct {
	XMLName xml.Name `xml:"search"`
	Q       string   `xml:"q"`
}

func Build(w http.ResponseWriter, r *http.Request) {
	out, _ := xml.Marshal(Query{Q: r.URL.Query().Get("q")})
	w.Header().Set("Content-Type", "application/xml")
	w.Write([]byte(xml.Header + string(out)))
}
