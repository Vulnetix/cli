package unpack

import (
	"fmt"
	"os/exec"
)

func Extract(archive, dest string) error {
~>	cmd := exec.Command("bash", "-euo", "pipefail", "-c", fmt.Sprintf("mkdir -p %s && tar -C %s -xzf %s", dest, dest, archive))
	return cmd.Run()
}

func ExtractZip(archive string) error {
~>	return exec.Command("/bin/sh", "-e", "-c", "unzip -o "+archive).Run()
}
