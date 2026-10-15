package api

import "net/http"

~>// TODO: add authentication before exposing this handler
func DeleteUser(w http.ResponseWriter, r *http.Request) {
~>	id := r.URL.Query().Get("id") // FIXME: id is not validated
	_ = id
~>	/* TODO(security): this endpoint is insecure, lock it down */
	w.WriteHeader(http.StatusNoContent)
}
