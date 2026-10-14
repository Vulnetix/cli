package main

import (
	"encoding/gob"
	"log"
	"net"
)

type Command struct {
	Op   string
	Args map[string]string
}

func main() {
	ln, err := net.Listen("tcp", ":7070")
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer conn.Close()
			var cmd Command
~>			if err := gob.NewDecoder(conn).Decode(&cmd); err != nil {
				return
			}
			log.Println(cmd.Op)
		}()
	}
}
