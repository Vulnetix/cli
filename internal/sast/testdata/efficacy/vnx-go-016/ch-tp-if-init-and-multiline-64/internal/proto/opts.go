package proto

import (
	"os"
	"strconv"
)

type Opts struct {
	Port  uint16
	Depth int16
}

func Load() Opts {
	var o Opts
	if n, err := strconv.Atoi(os.Getenv("APP_PORT")); err == nil {
~>		o.Port = uint16(n)
	}
	d, err := strconv.ParseInt(
		os.Getenv("APP_DEPTH"), 10, 64)
	if err == nil {
~>		o.Depth = int16(d)
	}
	return o
}
