package config

import "os"

const PasswordField = "password"

type Creds struct {
	User     string
	Password string
}

func FromEnv() Creds {
	return Creds{User: os.Getenv("DB_USER"), Password: os.Getenv("DB_PASSWORD")}
}

func Blank() Creds {
	return Creds{User: "app", Password: ""}
}

var dsn = "app:${DB_PASSWORD}@tcp(db:3306)/shop"
