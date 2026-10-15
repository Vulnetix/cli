package auth

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
)

func SaveToken(dir, token string) error {
~>	return os.WriteFile(filepath.Join(dir, "token"), []byte(token), 0644)
}

func SaveCredentials(path string, creds Credentials) error {
	data, _ := json.Marshal(creds)
~>	return ioutil.WriteFile(path+"/credentials.json", data,
		0o664)
}

func OpenSecretFile(secretPath string) (*os.File, error) {
~>	return os.OpenFile(secretPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
}
