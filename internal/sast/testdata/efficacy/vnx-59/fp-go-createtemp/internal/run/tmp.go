package run

import (
	"os"
	"path/filepath"
)

func Scratch() (string, error) {
	f, err := os.CreateTemp("", "agent-*.json")
	if err != nil {
		return "", err
	}
	defer f.Close()
	dir, err := os.MkdirTemp("", "agent")
	if err != nil {
		return "", err
	}
	out, err := os.Create(filepath.Join(dir, "out.json"))
	if err != nil {
		return "", err
	}
	defer out.Close()
	lock, err := os.OpenFile("/tmp/agent.lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	defer lock.Close()
	data, _ := os.ReadFile("/tmp/agent.conf")
	return string(data), nil
}
