package auth

import "os"

func SaveToken(path, token string) error {
	return os.WriteFile(path, []byte(token), 0600)
}

func SaveCreds(path string, data []byte) error {
	return os.WriteFile(path+"/credentials", data, 0o400)
}

func WriteReport(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

func OpenSecret(secretPath string) (*os.File, error) {
	return os.OpenFile(secretPath, os.O_CREATE|os.O_WRONLY, 0o600)
}
