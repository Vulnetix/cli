package api

import (
	"bytes"
	"encoding/gob"
	"io/ioutil"
	"net/http"
)

type Snapshot struct {
	Items map[string][]byte
}

func ImportSnapshot(w http.ResponseWriter, r *http.Request) {
	raw, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	buf := bytes.NewBuffer(raw)
	var snap Snapshot
~>	if err := gob.NewDecoder(buf).Decode(&snap); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	store(snap)
}

func store(Snapshot) {}
