package ok

import "os"

func Ok(dir string, data []byte) error {
	// os.MkdirAll(dir, 755) is the bug this avoids
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(dir+"/c", data, 0644)
}
