package files

import (
	"io"
	"net/http"
	"os"
	"path"
)

const uploadDir = "/var/www/html/files"

func Put(w http.ResponseWriter, r *http.Request) {
	f, header, err := r.FormFile("file")
	if err != nil {
		return
	}
	defer f.Close()
	name := header.Filename
~>	out, err := os.OpenFile(uploadDir+"/"+name, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return
	}
	defer out.Close()
	io.Copy(out, f)
}

func PutSmall(w http.ResponseWriter, req *http.Request) {
	f, hdr, err := req.FormFile("blob")
	if err != nil {
		return
	}
	data, _ := io.ReadAll(f)
~>	os.WriteFile(path.Join(uploadDir, hdr.Filename), data, 0o644)
}
