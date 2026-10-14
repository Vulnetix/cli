package cache

import (
	"encoding/gob"
	"net"
	"net/http"
	"os"
)

type Index struct{ Keys []string }

func Load(path string) (*Index, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var idx Index
	return &idx, gob.NewDecoder(f).Decode(&idx)
}

func FromPeer(addr string) (*Index, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var idx Index
	return &idx, gob.NewDecoder(conn).Decode(&idx)
}

// Handler streams the index to the caller; the request body is never decoded.
func Handler(w http.ResponseWriter, r *http.Request) {
	idx, _ := Load("/var/cache/index.gob")
	_ = r.Body.Close()
	gob.NewEncoder(w).Encode(idx)
}
