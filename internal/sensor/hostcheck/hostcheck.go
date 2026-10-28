// Package hostcheck reads a host's configuration and reports what fails the
// hardening guidance in the CIS Linux and Kubernetes benchmarks.
//
// The ids are Vulnetix's own (VNX-HOST-...), not CIS section numbers: the
// section numbers differ between benchmark editions and distributions, and a
// number that is wrong for the reader's edition is worse than none. Each check
// names the setting, which is how the benchmarks index them too.
//
// Only what a file on the host says is judged. A setting that cannot be read
// is not reported as failing, and a check that does not apply to the compute
// kind (IP forwarding on a Kubernetes node, which needs it) is skipped.
package hostcheck

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Finding is one failed check.
type Finding struct {
	ID       string
	Title    string
	Severity string
	// Path is the file the setting came from, on the host.
	Path   string
	Detail string
	Fix    string
}

// Run checks the host whose filesystem is at root. computeKind is the
// sensor's (eks-node skips checks Kubernetes needs to fail).
func Run(root, computeKind string) []Finding {
	var out []Finding
	out = append(out, sshd(root)...)
	out = append(out, permissions(root)...)
	out = append(out, sysctls(root, computeKind)...)
	out = append(out, dockerSocket(root)...)
	out = append(out, kubelet(root)...)

	return out
}

// ── sshd ────────────────────────────────────────────────────────────────────

// sshdConfig reads sshd_config and its Include files. sshd uses the first
// value it sees for a keyword, so the first one wins here too.
func sshdConfig(root string) (map[string]string, bool) {
	main := filepath.Join(root, "etc/ssh/sshd_config")
	if _, err := os.Stat(main); err != nil {
		return nil, false
	}
	values := map[string]string{}
	var read func(path string, depth int)
	read = func(path string, depth int) {
		f, err := os.Open(path)
		if err != nil || depth > 4 {
			return
		}
		defer func() { _ = f.Close() }()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
				continue
			}
			key := strings.ToLower(fields[0])
			if key == "match" {
				// Match blocks apply to some connections only; the global
				// setting is everything before the first one.
				return
			}
			if key == "include" {
				for _, pattern := range fields[1:] {
					if !filepath.IsAbs(pattern) {
						pattern = filepath.Join("/etc/ssh", pattern)
					}
					matches, _ := filepath.Glob(filepath.Join(root, pattern))
					for _, m := range matches {
						read(m, depth+1)
					}
				}

				continue
			}
			if _, set := values[key]; !set {
				values[key] = strings.ToLower(fields[1])
			}
		}
	}
	read(main, 0)

	return values, true
}

func sshd(root string) []Finding {
	values, ok := sshdConfig(root)
	if !ok {
		return nil
	}
	const path = "/etc/ssh/sshd_config"
	var out []Finding
	// sshd's own default for PermitRootLogin is prohibit-password, which
	// still allows key login as root.
	if v := values["permitrootlogin"]; v != "no" {
		out = append(out, Finding{ID: "VNX-HOST-SSH-ROOT", Severity: "high", Path: path,
			Title:  "SSH allows logging in as root",
			Detail: "PermitRootLogin is " + orDefault(v, "prohibit-password (the default)"),
			Fix:    "Set PermitRootLogin no and log in as a named user"})
	}
	if v := values["passwordauthentication"]; v == "" || v == "yes" {
		out = append(out, Finding{ID: "VNX-HOST-SSH-PASSWORD", Severity: "medium", Path: path,
			Title:  "SSH accepts passwords",
			Detail: "PasswordAuthentication is " + orDefault(v, "yes (the default)"),
			Fix:    "Set PasswordAuthentication no and use keys or SSM Session Manager"})
	}
	if values["permitemptypasswords"] == "yes" {
		out = append(out, Finding{ID: "VNX-HOST-SSH-EMPTY", Severity: "critical", Path: path,
			Title: "SSH accepts empty passwords", Detail: "PermitEmptyPasswords is yes", Fix: "Set PermitEmptyPasswords no"})
	}
	if values["x11forwarding"] == "yes" {
		out = append(out, Finding{ID: "VNX-HOST-SSH-X11", Severity: "low", Path: path,
			Title: "SSH forwards X11", Detail: "X11Forwarding is yes", Fix: "Set X11Forwarding no"})
	}
	if v, err := strconv.Atoi(values["maxauthtries"]); err == nil && v > 4 {
		out = append(out, Finding{ID: "VNX-HOST-SSH-TRIES", Severity: "low", Path: path,
			Title: "SSH allows more than 4 authentication attempts", Detail: fmt.Sprintf("MaxAuthTries is %d", v), Fix: "Set MaxAuthTries 4"})
	}

	return out
}

// ── file permissions ────────────────────────────────────────────────────────

func permissions(root string) []Finding {
	checks := []struct {
		path, id, title string
		max             fs.FileMode
		severity        string
	}{
		{"/etc/shadow", "VNX-HOST-PERM-SHADOW", "/etc/shadow is readable beyond root and the shadow group", 0o640, "high"},
		{"/etc/gshadow", "VNX-HOST-PERM-GSHADOW", "/etc/gshadow is readable beyond root and the shadow group", 0o640, "medium"},
		{"/etc/passwd", "VNX-HOST-PERM-PASSWD", "/etc/passwd is writable beyond root", 0o644, "high"},
		{"/etc/group", "VNX-HOST-PERM-GROUP", "/etc/group is writable beyond root", 0o644, "medium"},
		{"/etc/ssh/sshd_config", "VNX-HOST-PERM-SSHD", "sshd_config is writable beyond root", 0o644, "medium"},
	}
	var out []Finding
	for _, c := range checks {
		info, err := os.Stat(filepath.Join(root, c.path))
		if err != nil {
			continue
		}
		mode := info.Mode().Perm()
		if mode&^c.max != 0 {
			out = append(out, Finding{ID: c.id, Severity: c.severity, Path: c.path, Title: c.title,
				Detail: fmt.Sprintf("mode is %04o, at most %04o expected", mode, c.max),
				Fix:    fmt.Sprintf("chmod %04o %s", c.max, c.path)})
		}
	}

	return out
}

// ── kernel parameters ───────────────────────────────────────────────────────

func sysctl(root, name string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(root, "proc/sys", strings.ReplaceAll(name, ".", "/")))
	if err != nil {
		return "", false
	}

	return strings.TrimSpace(string(b)), true
}

func sysctls(root, computeKind string) []Finding {
	checks := []struct {
		name, want, id, title, severity string
		skipOn                          map[string]bool
	}{
		{"kernel.randomize_va_space", "2", "VNX-HOST-ASLR", "Address space layout randomisation is not fully on", "medium", nil},
		{"net.ipv4.conf.all.accept_redirects", "0", "VNX-HOST-REDIRECTS", "The host accepts ICMP redirects", "low", nil},
		{"net.ipv4.conf.all.send_redirects", "0", "VNX-HOST-SEND-REDIRECTS", "The host sends ICMP redirects", "low",
			map[string]bool{"eks-node": true, "ecs-ec2": true}},
		{"net.ipv4.ip_forward", "0", "VNX-HOST-FORWARD", "The host forwards IPv4 packets", "low",
			// Container hosts route between the bridge and the network.
			map[string]bool{"eks-node": true, "ecs-ec2": true, "ecs-fargate": true}},
		{"fs.suid_dumpable", "0", "VNX-HOST-SUID-DUMP", "setuid programs can dump core", "low", nil},
	}
	var out []Finding
	for _, c := range checks {
		if c.skipOn[computeKind] {
			continue
		}
		v, ok := sysctl(root, c.name)
		if !ok || v == c.want {
			continue
		}
		out = append(out, Finding{ID: c.id, Severity: c.severity, Path: "/proc/sys/" + strings.ReplaceAll(c.name, ".", "/"),
			Title: c.title, Detail: fmt.Sprintf("%s is %s, %s expected", c.name, v, c.want),
			Fix: fmt.Sprintf("sysctl -w %s=%s and persist it in /etc/sysctl.d", c.name, c.want)})
	}

	return out
}

// ── container runtimes ──────────────────────────────────────────────────────

func dockerSocket(root string) []Finding {
	info, err := os.Stat(filepath.Join(root, "var/run/docker.sock"))
	if err != nil || info.Mode().Perm()&0o002 == 0 {
		return nil
	}

	return []Finding{{ID: "VNX-HOST-DOCKER-SOCK", Severity: "critical", Path: "/var/run/docker.sock",
		Title:  "The Docker socket is writable by every user",
		Detail: fmt.Sprintf("mode is %04o; any user can start a privileged container and own the host", info.Mode().Perm()),
		Fix:    "chmod 660 /var/run/docker.sock and limit the docker group"}}
}

// kubelet reads the EKS AMI's kubelet config.
func kubelet(root string) []Finding {
	for _, rel := range []string{"etc/kubernetes/kubelet/kubelet-config.json", "etc/kubernetes/kubelet/config.json"} {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue
		}
		var cfg struct {
			Authentication struct {
				Anonymous struct {
					Enabled *bool `json:"enabled"`
				} `json:"anonymous"`
			} `json:"authentication"`
			Authorization struct {
				Mode string `json:"mode"`
			} `json:"authorization"`
			ReadOnlyPort *int `json:"readOnlyPort"`
		}
		if json.Unmarshal(b, &cfg) != nil {
			return nil
		}
		path := "/" + rel
		var out []Finding
		if a := cfg.Authentication.Anonymous.Enabled; a != nil && *a {
			out = append(out, Finding{ID: "VNX-HOST-KUBELET-ANON", Severity: "high", Path: path,
				Title: "The kubelet accepts anonymous requests", Detail: "authentication.anonymous.enabled is true",
				Fix: "Set authentication.anonymous.enabled to false"})
		}
		if m := cfg.Authorization.Mode; m == "AlwaysAllow" {
			out = append(out, Finding{ID: "VNX-HOST-KUBELET-AUTHZ", Severity: "high", Path: path,
				Title: "The kubelet authorises every request", Detail: "authorization.mode is AlwaysAllow",
				Fix: "Set authorization.mode to Webhook"})
		}
		if p := cfg.ReadOnlyPort; p != nil && *p != 0 {
			out = append(out, Finding{ID: "VNX-HOST-KUBELET-RO", Severity: "medium", Path: path,
				Title: "The kubelet serves its unauthenticated read-only port", Detail: fmt.Sprintf("readOnlyPort is %d", *p),
				Fix: "Set readOnlyPort to 0"})
		}

		return out
	}

	return nil
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}

	return v
}
