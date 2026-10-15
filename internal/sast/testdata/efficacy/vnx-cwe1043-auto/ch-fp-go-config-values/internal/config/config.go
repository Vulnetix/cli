package config

import "time"

type Config struct {
	Addr         string        `yaml:"addr"`
	Port         int           `yaml:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	Debug        bool          `yaml:"debug"`
	Tags         []string      `yaml:"tags"`
	Labels       map[string]string
	MaxConns     int64
	Ratio        float64
	Name, Owner  string
	Started      time.Time
	Token        []byte
	Err          error
}
