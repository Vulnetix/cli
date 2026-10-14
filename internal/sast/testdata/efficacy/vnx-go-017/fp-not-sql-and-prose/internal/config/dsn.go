package config

import (
	"fmt"
	"log"
)

type DB struct {
	Host, Port, Name, User, Password string
}

// A connection string, a STIX pattern and log lines are not SQL statements.
func (c DB) DSN() string {
	return fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=require",
		c.Host, c.Port, c.Name, c.User, c.Password)
}

func pattern(ip string) string {
	return fmt.Sprintf("[ipv4-addr:value = '%s']", ip)
}

func note(table, who string) {
	log.Printf("select from %s requested by '%s'", table, who)
	msg := fmt.Sprintf("delete of '%s' was refused", who)
	log.Println(msg)
	help := "never write db.Query(fmt.Sprintf(\"SELECT * FROM users WHERE name = '%s'\", name))"
	log.Println(help)
	// db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
	cacheKey := fmt.Sprintf("user=%s", who)
	log.Println(cacheKey)
}
