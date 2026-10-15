package db

// go-sql-driver DSN: user:password@tcp(host)/db, not a URL; built from config.
func dsn(c Config) string { return c.User + ":" + c.Pass + "@tcp(" + c.Host + ")/app" }
