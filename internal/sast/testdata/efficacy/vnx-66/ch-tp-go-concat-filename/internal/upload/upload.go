package upload

import (
	"io"
	"net/http"
	"os"
)

func Handle(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "bad upload", http.StatusBadRequest)
		return
	}
	defer file.Close()
~>	dst, err := os.Create("./uploads/" + header.Filename)
	if err != nil {
		http.Error(w, "cannot store", http.StatusInternalServerError)
		return
	}
	defer dst.Close()
	io.Copy(dst, file)
}
