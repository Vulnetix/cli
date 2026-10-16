package cache

import (
	"encoding/gob"
	"net/http"
	"os"
)

func Load(path string) (*State, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var s State
	if err := gob.NewDecoder(f).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

func Dump(w http.ResponseWriter, r *http.Request) {
	gob.NewEncoder(w).Encode(current())
}
