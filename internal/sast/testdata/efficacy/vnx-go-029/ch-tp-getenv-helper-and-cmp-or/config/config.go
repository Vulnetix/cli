package config

import (
	"cmp"
	"os"
)

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

type DB struct {
	User     string
	Password string
}

func Load() DB {
	return DB{
		User:     getEnv("DB_USER", "app"),
~>		Password: getEnv("DB_PASSWORD", "changeme"),
	}
}

func AdminPassword() string {
~>	return cmp.Or(os.Getenv("ADMIN_PASSWORD"), "admin123")
}
