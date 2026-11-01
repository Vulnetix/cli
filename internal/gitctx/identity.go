package gitctx

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ConfigIdentity is the user.name and user.email git would stamp on a commit
// made from a directory. It is what the person running the CLI claims to be,
// and nothing checks it.
type ConfigIdentity struct {
	Name  string
	Email string
}

var configIdentityCache sync.Map // dir -> ConfigIdentity

// ConfigUser reads user.name and user.email with `git config --get` from dir
// (the process directory when dir is ""). A missing git binary, a directory
// outside any repository and an unset key all give empty fields. Cached per
// directory, because every request in a run asks.
func ConfigUser(dir string) ConfigIdentity {
	if v, ok := configIdentityCache.Load(dir); ok {
		return v.(ConfigIdentity)
	}
	id := ConfigIdentity{Name: gitConfigGet(dir, "user.name"), Email: gitConfigGet(dir, "user.email")}
	configIdentityCache.Store(dir, id)
	return id
}

func gitConfigGet(dir, key string) string {
	if _, err := exec.LookPath("git"); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	args := []string{"config", "--get", key}
	if dir != "" {
		args = append([]string{"-C", dir}, args...)
	}
	out, err := exec.CommandContext(ctx, "git", args...).Output()
	if err != nil {
		// Exit status 1 means the key is unset, which is an answer, not a fault.
		return ""
	}
	return strings.TrimSpace(string(out))
}

// LocalActor is the best identity this machine can claim for a decision
// written to memory.yaml: the git config email for dir, else user@host, else
// the bare user name. "" when none of them can be read.
func LocalActor(dir string) string {
	if email := ConfigUser(dir).Email; email != "" {
		return email
	}
	return osActor(CollectSystemInfo())
}

func osActor(sys *SystemInfo) string {
	if sys == nil || sys.Username == "" {
		return ""
	}
	if sys.Hostname == "" {
		return sys.Username
	}
	return sys.Username + "@" + sys.Hostname
}
