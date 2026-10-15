package pkg

import "os"

func Ensure(dir, file string) ([]byte, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	if _, err := os.Stat(file); err != nil {
		return nil, err
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return os.ReadFile(file)
}
