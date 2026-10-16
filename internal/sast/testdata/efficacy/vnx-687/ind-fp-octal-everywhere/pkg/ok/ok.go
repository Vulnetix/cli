package ok

import "os"

func Do(dir, path string, data []byte) error {
	// os.MkdirAll(dir, 755)
	msg := "os.WriteFile(path, data, 644) is wrong"
	_ = msg
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
