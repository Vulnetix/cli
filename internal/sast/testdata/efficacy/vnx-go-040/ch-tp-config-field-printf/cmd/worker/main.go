package main

import (
	"log"
	"os"
)

type config struct {
	DBHost     string
	DBPassword string
}

func main() {
	cfg := config{DBHost: os.Getenv("DB_HOST"), DBPassword: os.Getenv("DB_PASSWORD")}
~>	log.Printf("connecting to %s with %s", cfg.DBHost, cfg.DBPassword)
}
