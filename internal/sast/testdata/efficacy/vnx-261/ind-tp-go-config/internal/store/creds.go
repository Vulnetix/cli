package store

import (
	"encoding/base64"
	"os"
)

type Creds struct {
	User     string
	Password string
}

func Save(path, user, dbPassword string) error {
	c := Creds{User: user}
~>	c.Password = base64.StdEncoding.EncodeToString([]byte(dbPassword))
	return writeJSON(path, c, os.FileMode(0o600))
}
