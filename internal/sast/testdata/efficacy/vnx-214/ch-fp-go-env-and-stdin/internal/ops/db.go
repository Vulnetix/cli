package ops

import (
	"os"
	"os/exec"
	"strings"
)

func Dump(user, password, db string) error {
	cmd := exec.Command("mysqldump", "-u", user, db)
	cmd.Env = append(os.Environ(), "MYSQL_PWD="+password)
	return cmd.Run()
}

func Login(registry, user, token string) error {
	cmd := exec.Command("docker", "login", registry, "-u", user, "--password-stdin")
	cmd.Stdin = strings.NewReader(token)
	return cmd.Run()
}
