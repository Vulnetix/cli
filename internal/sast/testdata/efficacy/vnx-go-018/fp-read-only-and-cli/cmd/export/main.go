package main

import (
	"flag"
	"net/http"
	"os"
	"path/filepath"
)

// The operator who runs the tool chooses the output path; that is not an
// attacker.
func main() {
	out := flag.String("out", "report.json", "output file")
	flag.Parse()
	os.WriteFile(*out, []byte("{}"), 0o644)
	if len(os.Args) > 2 {
		os.Create(os.Args[2])
	}
}

// Opening for reading is path traversal of a different kind (VNX-GO-027), not
// a write.
func Download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	f, err := os.Open(filepath.Join("/srv/public", name))
	if err == nil {
		f.Close()
	}
	g, err := os.OpenFile(filepath.Join("/srv/public", name), os.O_RDONLY, 0)
	if err == nil {
		g.Close()
	}
	// os.WriteFile(filepath.Join(dir, r.FormValue("name")), data, 0o644)
}
