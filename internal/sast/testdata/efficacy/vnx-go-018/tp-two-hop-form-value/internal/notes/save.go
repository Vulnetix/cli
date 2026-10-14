package notes

import (
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
)

type Store struct {
	Root string
}

// name comes from the form, p is joined from it, and p is written.
func (s *Store) Save(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	body := []byte(r.FormValue("body"))
	p := filepath.Join(s.Root, name)
~>	if err := os.WriteFile(p, body, 0o600); err != nil {
		http.Error(w, "save failed", http.StatusInternalServerError)
	}
}

// filepath.Clean does not confine a joined path: Clean("/srv/../../etc") is
// "/etc".
func (s *Store) Append(w http.ResponseWriter, r *http.Request) {
	dest := filepath.Clean(filepath.Join(s.Root, r.URL.Query().Get("file")))
~>	f, err := os.OpenFile(dest, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
}

func (s *Store) Legacy(w http.ResponseWriter, r *http.Request) {
~>	ioutil.WriteFile(path.Join(s.Root, r.PostFormValue("path")), []byte("x"), 0o600)
}
