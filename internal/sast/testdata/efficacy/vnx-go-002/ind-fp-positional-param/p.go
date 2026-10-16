package ops

import "os/exec"

func Count(path string) ([]byte, error) {
	return exec.Command("sh", "-c", `wc -l "$1"`, "sh", path).Output()
}
