package feeds

import "net/http"

type params struct{ Format string }

func parseParams(q map[string][]string) params {
	if f := q["format"]; len(f) > 0 && f[0] == "csv" {
		return params{Format: "csv"}
	}
	return params{Format: "json"}
}

func (p params) contentType() string {
	if p.Format == "csv" {
		return "text/csv"
	}
	return "application/json"
}

func Feed(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p := parseParams(q)
	w.Header().Set("Content-Type", p.contentType())
	w.Header().Set("X-Format", p.Format)
}
