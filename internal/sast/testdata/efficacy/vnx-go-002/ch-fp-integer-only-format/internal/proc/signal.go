package proc

import (
	"fmt"
	"os/exec"
	"strconv"
)

// Alive reports whether the worker with this pid still runs. The pid is an
// int, so the formatted script cannot carry shell syntax.
func Alive(pid int) bool {
	return exec.Command("sh", "-c", fmt.Sprintf("kill -0 %d 2>/dev/null", pid)).Run() == nil
}

func Renice(pid, prio int) error {
	return exec.Command("sh", "-c", "renice -n "+strconv.Itoa(prio)+" -p "+strconv.Itoa(pid)).Run()
}
