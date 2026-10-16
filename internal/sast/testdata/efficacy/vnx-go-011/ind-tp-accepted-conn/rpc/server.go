package rpc

import (
	"encoding/gob"
	"net"
)

func Serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			var cmd Command
~>			gob.NewDecoder(conn).Decode(&cmd)
			run(cmd)
		}()
	}
}
