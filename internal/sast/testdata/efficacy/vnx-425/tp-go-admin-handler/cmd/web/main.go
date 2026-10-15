package main

import (
	"fmt"
	"net/http"
)

func adminDashboard(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "orders today: 42")
}

func (s *server) adminPurge(w http.ResponseWriter, r *http.Request) {
	s.cache.Purge()
}

type server struct{ cache interface{ Purge() } }

func main() {
	s := &server{}
~>	http.HandleFunc("/admin/dashboard", adminDashboard)
~>	http.HandleFunc("/admin/purge", s.adminPurge)
	http.ListenAndServe(":8080", nil)
}
