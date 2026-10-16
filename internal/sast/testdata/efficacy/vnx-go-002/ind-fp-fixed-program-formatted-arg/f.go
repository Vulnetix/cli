package ops

import (
	"fmt"
	"os/exec"
)

func Resize(id int, w int) error {
	size := fmt.Sprintf("%dx%d", w, w)
	return exec.Command("convert", fmt.Sprintf("in-%d.png", id), "-resize", size, "out.png").Run()
}
