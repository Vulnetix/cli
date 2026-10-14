package files

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func Stream(w http.ResponseWriter, r *http.Request) {
	mr, err := r.MultipartReader()
	if err != nil {
		return
	}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if part.FileName() == "" {
			continue
		}
~>		out, err := os.Create(
			filepath.Join(uploadDir, part.FileName()),
		)
		if err != nil {
			return
		}
		io.Copy(out, part)
		out.Close()
	}
}
