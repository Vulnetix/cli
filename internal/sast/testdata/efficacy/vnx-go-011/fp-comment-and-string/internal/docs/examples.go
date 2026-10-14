package docs

import "net/http"

// Never write gob.NewDecoder(r.Body).Decode(&v) in a handler; decode JSON.
const antiPattern = "gob.NewDecoder(r.Body).Decode(&v)"

func Example(w http.ResponseWriter, r *http.Request) {
	// dec := gob.NewDecoder(r.Body)
	w.Write([]byte(antiPattern))
}
