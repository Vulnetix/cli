package cache

import (
	"os"
	"path/filepath"
)

func Open() (*os.File, error) {
~>	return os.OpenFile(filepath.Join(os.TempDir(), "cache.db"), os.O_RDWR|os.O_CREATE, 0o600)
}

func Dump(b []byte) error {
	name := "/tmp/cache-dump.json"
~>	return os.WriteFile(name, b, 0o644)
}
