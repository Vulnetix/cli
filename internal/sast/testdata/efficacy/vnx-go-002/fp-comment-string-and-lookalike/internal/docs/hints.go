package docs

import (
	"fmt"

	"example.com/remote/sshexec"
)

// Never write exec.Command("sh", "-c", fmt.Sprintf("ping %s", host)): pass
// the host as its own argument instead.
const antiPattern = `exec.Command("sh", "-c", fmt.Sprintf("ping %s", host))`

func Explain() string {
	return fmt.Sprintf("avoid: %s", antiPattern)
}

// sshexec.Command runs on a remote host through its own quoting layer; it is
// not os/exec.
func Uptime(host string) error {
	return sshexec.Command(fmt.Sprintf("uptime %s", host)).Run()
}
