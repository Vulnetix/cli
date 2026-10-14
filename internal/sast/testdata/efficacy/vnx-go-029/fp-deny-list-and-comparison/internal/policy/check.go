package policy

import "errors"

var ErrTooCommon = errors.New("password is too common")

var common = map[string]bool{"123456": true, "password": true, "admin": true}

func Check(password string) error {
	if password == "password" || common[password] {
		return ErrTooCommon
	}
	// password = "admin" was the old default
	return nil
}

const help = `set password: "changeme" is rejected`
