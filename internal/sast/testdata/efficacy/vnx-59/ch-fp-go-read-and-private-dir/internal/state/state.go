package state

import "os"

func Load() ([]byte, error) {
	return os.ReadFile("/tmp/state.json")
}

func Save(b []byte) error {
	dir, err := os.MkdirTemp("", "state-")
	if err != nil {
		return err
	}
	if err := os.WriteFile(dir+"/state.json", b, 0o600); err != nil {
		return err
	}
	return os.WriteFile("/var/lib/app/state.json", b, 0o600)
}
