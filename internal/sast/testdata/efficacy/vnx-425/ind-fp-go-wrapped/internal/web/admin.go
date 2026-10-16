package web

import "net/http"

func RegisterAdmin(mux *http.ServeMux) {
	mux.Handle("/admin/users", requireAdmin(http.HandlerFunc(listUsers)))
	mux.HandleFunc("/admin/audit", auditLog)
}

func auditLog(w http.ResponseWriter, r *http.Request) {
	user, ok := sessionUser(r)
	if !ok || !user.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	writeAudit(w)
}
