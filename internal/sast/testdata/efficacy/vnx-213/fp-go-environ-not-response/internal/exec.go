package internal

import (
	"os"
	"os/exec"
)

func Run(name string) error {
	cmd := exec.Command(name)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	return cmd.Run()
}

func Port() string {
	return os.Getenv("PORT")
}
