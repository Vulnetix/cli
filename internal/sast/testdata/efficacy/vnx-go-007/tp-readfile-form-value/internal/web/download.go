package web

import (
	"io/ioutil"
	"net/http"
	"os"
)

func Download(w http.ResponseWriter, r *http.Request) {
~>	data, err := os.ReadFile("/var/app/uploads/" + r.FormValue("file"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Write(data)
}

func Legacy(w http.ResponseWriter, req *http.Request) {
	name := req.URL.Query().Get("doc")
~>	b, _ := ioutil.ReadFile("docs/" + name)
	w.Write(b)
}
