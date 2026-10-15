package sync

import "os/exec"

func push(url string) error {
~>	cmd := exec.Command("curl", "-sS", "-u", "svc-sync:Tz84kWq2Lp", url)
	return cmd.Run()
}
