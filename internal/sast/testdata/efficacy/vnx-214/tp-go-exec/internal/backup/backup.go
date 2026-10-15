package backup

import (
	"context"
	"os/exec"
)

func Dump(user, password, db string) error {
~>	return exec.Command("mysqldump", "-u", user, "-p"+password, db).Run()
}

func Deploy(ctx context.Context, host, pass string) error {
~>	cmd := exec.CommandContext(ctx, "sshpass", "-p", pass, "ssh", host)
	return cmd.Run()
}

func Login(token string) error {
~>	return exec.Command("registryctl", "login", "--token="+token).Run()
}
