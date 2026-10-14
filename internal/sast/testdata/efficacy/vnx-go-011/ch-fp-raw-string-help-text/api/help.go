package api

import (
	"encoding/gob"
	"net/http"
	"os"
)

const unsafeExample = `dec := gob.NewDecoder(r.Body)`

func Help(w http.ResponseWriter, r *http.Request) {
	msg := `do not write gob.NewDecoder(r.Body) in a handler`
	w.Write([]byte(msg + unsafeExample))
	f, err := os.Open("/var/lib/app/state.gob")
	if err != nil {
		return
	}
	defer f.Close()
	var state map[string]int
	gob.NewDecoder(f).Decode(&state)
}
