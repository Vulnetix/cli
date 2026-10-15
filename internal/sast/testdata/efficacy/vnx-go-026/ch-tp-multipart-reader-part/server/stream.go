package server

import (
	"io"
	"net/http"
	"os"
)

func streamUpload(w http.ResponseWriter, r *http.Request) {
	reader, err := r.MultipartReader()
	if err != nil {
		return
	}
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
~>		out, err := os.Create("/var/www/files/" + part.FileName())
		if err != nil {
			return
		}
		io.Copy(out, part)
		out.Close()
	}
}
