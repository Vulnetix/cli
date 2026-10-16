package win

import (
	"fmt"
	"os/exec"
)

func Kill(name string) error {
~>	return exec.Command("cmd", "/C", fmt.Sprintf("taskkill /IM %s /F", name)).Run()
}
