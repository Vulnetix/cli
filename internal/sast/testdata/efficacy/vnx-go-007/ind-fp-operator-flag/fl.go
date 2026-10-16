package main

import (
	"flag"
	"os"
)

func main() {
	cfg := flag.String("config", "app.yaml", "config path")
	flag.Parse()
	os.ReadFile(*cfg)
}
