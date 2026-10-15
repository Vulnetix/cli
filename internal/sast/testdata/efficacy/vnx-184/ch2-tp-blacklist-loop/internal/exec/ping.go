package exec

import (
	"errors"
	"os/exec"
	"strings"
)

func Ping(host string) error {
~>	for _, bad := range []string{";", "&&", "|", "`"} {
		if strings.Contains(host, bad) {
			return errors.New("invalid host")
		}
	}
	return exec.Command("sh", "-c", "ping -c 1 "+host).Run()
}
