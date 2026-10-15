package report

import (
	"os"
	"path/filepath"
)

func Write(cfg Config) error {
	return os.WriteFile(filepath.Join(cfg.Dir, cfg.Filename), nil, 0o644)
}
