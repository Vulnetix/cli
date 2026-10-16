package setup

import "os"

func MarkHelper(path string) error {
~>	return os.Chmod(path, 0o755|os.ModeSetuid)
}
