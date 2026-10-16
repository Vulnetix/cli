package auth

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
)

type Credentials struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func configDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "acmectl")
}

// SaveCredentials persists the OAuth tokens for the next run.
func SaveCredentials(c Credentials) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return err
	}
~>	return os.WriteFile(filepath.Join(configDir(), "credentials.json"), data, 0644)
}

func SaveAPIKey(apiKey string) error {
~>	return ioutil.WriteFile(filepath.Join(configDir(), "api_key"), []byte(apiKey), 0o640)
}

func AppendToken(token string) error {
~>	f, err := os.OpenFile(filepath.Join(configDir(), "token"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(token)
	return err
}

func SaveSecret(secret string) error {
~>	f, err := os.Create(filepath.Join(configDir(), "secret"))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(secret)
	return err
}
