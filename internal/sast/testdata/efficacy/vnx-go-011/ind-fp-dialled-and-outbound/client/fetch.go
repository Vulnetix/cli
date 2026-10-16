package client

import (
	"encoding/gob"
	"net"
	"net/http"
)

func Call(addr string) (Reply, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return Reply{}, err
	}
	defer conn.Close()
	var rep Reply
	err = gob.NewDecoder(conn).Decode(&rep)
	return rep, err
}

func Pull(url string) (Reply, error) {
	resp, err := http.Get(url)
	if err != nil {
		return Reply{}, err
	}
	defer resp.Body.Close()
	var rep Reply
	err = gob.NewDecoder(resp.Body).Decode(&rep)
	return rep, err
}
