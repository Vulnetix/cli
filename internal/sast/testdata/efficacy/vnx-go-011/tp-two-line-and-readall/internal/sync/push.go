package sync

import (
	"bytes"
	"encoding/gob"
	"io"
	"net/http"
)

type Snapshot struct {
	Rows map[string][]byte
}

func Push(w http.ResponseWriter, req *http.Request) {
	body := req.Body
	defer body.Close()
~>	dec := gob.NewDecoder(body)
	var s Snapshot
	if err := dec.Decode(&s); err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
}

func Replay(w http.ResponseWriter, req *http.Request) {
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return
	}
	rd := bytes.NewReader(raw)
	var s Snapshot
~>	_ = gob.NewDecoder(rd).Decode(&s)
}
