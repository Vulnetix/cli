package db

import (
	"flag"
	"fmt"
	"os"
)

func DSN() string {
	pw := os.Getenv("DB_PASSWORD")
	if pw == "" {
		pw = getenv("DB_PASSWORD", "")
	}
	return "postgres://app:" + pw + "@db:5432/app"
}

func Template() string {
	return fmt.Sprintf("postgres://%s:%s@%s/app", os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), "db")
}

var placeholder = Config{Password: "${DB_PASSWORD}"}

var strong = flag.String("password", "", "database password (required)")

func getenv(k, def string) string { return def }

type Config struct{ Password string }
