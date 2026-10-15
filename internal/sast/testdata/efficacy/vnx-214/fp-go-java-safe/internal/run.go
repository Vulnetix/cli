package internal

import (
	"os"
	"os/exec"
)

func Dump(password string) error {
	cmd := exec.Command("mysqldump", "-u", "root", "shop")
	cmd.Env = append(os.Environ(), "MYSQL_PWD="+password)
	return cmd.Run()
}

func Serve(port string) error {
	return exec.Command("docker", "run", "-p", port+":80", "nginx").Run()
}
