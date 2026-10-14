package cluster

import (
	"encoding/gob"
	"log"
	"net"
)

type Gossip struct {
	From  string
	State map[string]int
}

func ServeTCP(ln *net.TCPListener) {
	for {
		tc, err := ln.AcceptTCP()
		if err != nil {
			log.Println(err)
			continue
		}
		var g Gossip
~>		if err := gob.NewDecoder(tc).Decode(&g); err != nil {
			tc.Close()
			continue
		}
		merge(g)
	}
}

func ServeUnix(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
~>		decoder := gob.NewDecoder(conn)
		var g Gossip
		_ = decoder.Decode(&g)
		conn.Close()
	}
}

func merge(Gossip) {}
