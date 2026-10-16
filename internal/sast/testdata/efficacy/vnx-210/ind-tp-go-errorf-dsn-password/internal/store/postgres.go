package store

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type Config struct {
	Host     string
	User     string
	Password string
	Name     string
}

func Open(cfg Config) (*sql.DB, error) {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=require", cfg.Host, cfg.User, cfg.Password, cfg.Name)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
~>		return nil, fmt.Errorf("open postgres with %q: %w", dsn, err)
	}
	if err := db.Ping(); err != nil {
~>		return nil, fmt.Errorf("ping %s as %s/%s: %w", cfg.Host, cfg.User, cfg.Password, err)
	}
	return db, nil
}
