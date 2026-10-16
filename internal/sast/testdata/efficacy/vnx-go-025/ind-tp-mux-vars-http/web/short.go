package web

import (
	"net/http"

	"github.com/gorilla/mux"
)

func Jump(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dest := vars["dest"]
	log.Printf("jump %s", dest)
~>	http.Redirect(w, r, dest, http.StatusMovedPermanently)
}
