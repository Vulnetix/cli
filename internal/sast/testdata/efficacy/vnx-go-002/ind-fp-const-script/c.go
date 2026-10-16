package ops

import "os/exec"

func Free() ([]byte, error) {
	return exec.Command("sh", "-c", "df -h | head -5").Output()
}
