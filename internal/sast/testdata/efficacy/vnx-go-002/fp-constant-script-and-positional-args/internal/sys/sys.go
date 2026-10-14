package sys

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"

	"github.com/alessio/shellescape"
)

const diskScript = "df -h / | tail -1"

// A constant script has nothing to inject.
func DiskUsage() ([]byte, error) {
	return exec.Command("sh", "-c", diskScript).Output()
}

func LogLines() ([]byte, error) {
	return exec.Command("sh", "-c", "ls -la /var/log | wc -l").Output()
}

// The value travels as a positional parameter ($1), never as script text.
func Greet(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, "sh", "-c", `printf 'hello %s\n' "$1"`, "sh", name).Run()
}

// Quoted for the shell before it is spliced in.
func Grep(pattern string) ([]byte, error) {
	return exec.Command("sh", "-c", "grep -rn "+shellescape.Quote(pattern)+" .").Output()
}

// No shell: each argument reaches the program as one argv entry.
func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, _ := exec.Command("ping", "-c", "1", "--", host).Output()
	w.Write(out)
}

// The Sprintf after the call is not one of its arguments.
func Kernel(host string, n int) (string, error) {
	cmd := exec.Command(
		"sh", "-c", "uname -a",
	)
	label := fmt.Sprintf("%s-%d", host, n)
	out, err := cmd.Output()
	return label + string(out), err
}

func Log(sha string) ([]byte, error) {
	msg := fmt.Sprintf("showing %s", sha)
	_ = msg
	return exec.Command("git", "log", "-1", "--format=%H %s", sha).Output()
}
