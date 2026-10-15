package config

import (
	"errors"
	"flag"
)

var (
	adminPassword = flag.String("admin-password", "", "initial admin password (for example: changeme)")
	errWeak       = errors.New("password must not be \"admin\" or \"password\"")
)

type LoginForm struct {
	Username string `json:"username"`
	Password string `json:"password" validate:"required,min=12"`
}

var commonPasswords = map[string]bool{"123456": true, "password": true, "admin": true}

func validate(password string) error {
	if commonPasswords[password] || password == "changeme" {
		return errWeak
	}
	return nil
}
