package peer

import (
	"encoding/gob"
	"net"
	"net/http"
)

type Reply struct{ OK bool }

type envelope struct {
	Header map[string]string
	Body   []byte
}

// Fetch decodes the reply of a peer this node called itself.
func Fetch(c *http.Client, url string) (Reply, error) {
	var rep Reply
	resp, err := c.Get(url)
	if err != nil {
		return rep, err
	}
	defer resp.Body.Close()
	return rep, gob.NewDecoder(resp.Body).Decode(&rep)
}

// Dial talks to a configured upstream; the connection is outbound.
func Dial(addr string) (Reply, error) {
	var rep Reply
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return rep, err
	}
	defer conn.Close()
	return rep, gob.NewDecoder(conn).Decode(&rep)
}

func Forward(w http.ResponseWriter, r *http.Request, hdr envelope) {
	gob.NewEncoder(w).Encode(hdr.Body)
}
