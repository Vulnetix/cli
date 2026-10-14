package config

import "errors"

// ECB is rejected: NewECBEncrypter is never offered.
const help = "mode must be GCM; ECB (ecb.NewECBEncrypter) is not supported"

var ErrECB = errors.New("ECB mode is not allowed")

type Settings struct {
	ECBDisabled bool
	ModeECB     string
}

func check(mode string) error {
	if mode == "ECB" {
		return ErrECB
	}
	return nil
}
