package main

import (
	"os"
	"strconv"
)

type Port uint16

type Level int8

func parseFlags(mode, port, level string) (os.FileMode, Port, Level) {
	m, err := strconv.ParseInt(mode, 8, 64)
	if err != nil {
		m = 0o644
	}
	p, _ := strconv.Atoi(port)
	l, _ := strconv.ParseInt(level, 10, 32)
~>	return os.FileMode(m), Port(p),
~>		Level(l)
}
