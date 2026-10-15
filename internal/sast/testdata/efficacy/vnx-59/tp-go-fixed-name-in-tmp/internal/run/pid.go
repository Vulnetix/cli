package run

import (
	"os"
	"path/filepath"
	"strconv"
)

func WritePID() error {
~>	f, err := os.Create("/tmp/agent.pid")
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(strconv.Itoa(os.Getpid()))
	return err
}

func SaveToken(tok []byte) error {
~>	return os.WriteFile("/tmp/agent.token", tok, 0o600)
}

func OpenLog() (*os.File, error) {
~>	return os.OpenFile("/tmp/agent.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
}

func Lock() (*os.File, error) {
	lock := filepath.Join(os.TempDir(), "agent.lock")
~>	return os.Create(lock)
}
