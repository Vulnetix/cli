package main

import (
	"fmt"
	"log"
	"os"
)

func writePID() error {
~>	f, err := os.Create("/tmp/agent.pid")
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%d\n", os.Getpid())
	return err
}

func main() {
	if err := writePID(); err != nil {
		log.Fatal(err)
	}
	run()
}
