package main

import (
	"net/http"
)

func adminDashboard(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(r)
	if !ok || !user.Admin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Write([]byte("ok"))
}

func main() {
	http.HandleFunc("/admin/dashboard", adminDashboard)
	http.Handle("/admin/purge", requireAdmin(http.HandlerFunc(purge)))
	http.HandleFunc("/admin/imported", handlers.AdminImported)
	http.HandleFunc("/products", products)
	http.ListenAndServe(":8080", nil)
}
