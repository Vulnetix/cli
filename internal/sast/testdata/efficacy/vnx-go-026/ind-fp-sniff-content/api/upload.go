package api

import (
	"io"
	"net/http"
	"os"
)

func Upload(w http.ResponseWriter, r *http.Request) {
	file, handler, err := r.FormFile("pic")
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer file.Close()
	head := make([]byte, 512)
	n, _ := file.Read(head)
	if http.DetectContentType(head[:n]) != "image/png" {
		http.Error(w, "png only", 400)
		return
	}
	file.Seek(0, io.SeekStart)
	dst, _ := os.Create("/data/pics/" + handler.Filename)
	defer dst.Close()
	io.Copy(dst, file)
}
