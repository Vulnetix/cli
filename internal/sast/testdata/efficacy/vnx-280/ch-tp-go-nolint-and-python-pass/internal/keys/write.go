package keys

import "os"

func Save(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
~>	os.Chmod(path, 0o600) //nolint:errcheck
	return nil
}
