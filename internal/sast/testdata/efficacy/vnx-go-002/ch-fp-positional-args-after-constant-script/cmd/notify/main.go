package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	title := os.Args[1]
	// The script is a constant; the formatted values are positional
	// parameters, which the shell never parses as code.
	cmd := exec.Command("sh", "-c", `notify-send "$1" "$2"`, "sh", fmt.Sprintf("Build %s", title), "finished")
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
