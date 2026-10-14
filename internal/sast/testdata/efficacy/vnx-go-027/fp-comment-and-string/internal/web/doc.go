package web

import "log"

// Bad: os.ReadFile(filepath.Join(base, r.FormValue("f")))
func note() {
	log.Println("never call os.Open(r.FormValue(\"f\")) directly")
}
