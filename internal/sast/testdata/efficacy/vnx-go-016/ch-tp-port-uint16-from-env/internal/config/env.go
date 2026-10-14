package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port    uint16
	Workers int32
}

func FromEnv() (Config, error) {
	var c Config
	p, err := strconv.Atoi(os.Getenv("PORT"))
	if err != nil {
		return c, err
	}
~>	c.Port = uint16(p)

	w, err := strconv.ParseInt(os.Getenv("WORKERS"), 10, 64)
	if err != nil {
		return c, err
	}
	if w <= 0 {
		w = 4
	}
~>	c.Workers = int32(w)
	return c, nil
}
