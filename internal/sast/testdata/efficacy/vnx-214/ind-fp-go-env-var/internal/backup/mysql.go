package backup

import (
	"os"
	"os/exec"
)

func Dump(user, password, db string) ([]byte, error) {
	cmd := exec.Command("mysqldump", "-u", user, db)
	cmd.Env = append(os.Environ(), "MYSQL_PWD="+password)
	return cmd.Output()
}

func Login(user string) error {
	cmd := exec.Command("mysql", "-u", user, "-p")
	cmd.Stdin = os.Stdin
	return cmd.Run()
}
