package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func Asset(w http.ResponseWriter, r *http.Request) {
	rel := mux.Vars(r)["path"]
~>	http.ServeFile(w, r, "/srv/assets/"+rel)
}
