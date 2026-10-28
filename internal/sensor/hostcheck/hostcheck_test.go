package hostcheck

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, root, rel, body string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func ids(fs []Finding) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range fs {
		out[f.ID] = f
	}

	return out
}

func TestRunFindsWeakConfiguration(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nMaxAuthTries 6\nMatch User backup\n  PasswordAuthentication yes\n", 0o644)
	write(t, root, "etc/ssh/sshd_config.d/10-cloud.conf", "PasswordAuthentication no\nX11Forwarding yes\n", 0o644)
	write(t, root, "etc/shadow", "", 0o644)
	write(t, root, "etc/passwd", "", 0o644)
	write(t, root, "proc/sys/kernel/randomize_va_space", "1\n", 0o644)
	write(t, root, "proc/sys/net/ipv4/ip_forward", "1\n", 0o644)
	write(t, root, "var/run/docker.sock", "", 0o666)
	write(t, root, "etc/kubernetes/kubelet/kubelet-config.json",
		`{"authentication":{"anonymous":{"enabled":true}},"authorization":{"mode":"Webhook"},"readOnlyPort":10255}`, 0o644)

	got := ids(Run(root, "ec2"))
	for _, want := range []string{
		"VNX-HOST-SSH-ROOT", "VNX-HOST-SSH-TRIES", "VNX-HOST-SSH-X11", "VNX-HOST-PERM-SHADOW",
		"VNX-HOST-ASLR", "VNX-HOST-FORWARD", "VNX-HOST-DOCKER-SOCK", "VNX-HOST-KUBELET-ANON", "VNX-HOST-KUBELET-RO",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s", want)
		}
	}
	// The Include came first, so its "no" is the global value; the Match
	// block applies to one user and is not the global setting.
	if _, ok := got["VNX-HOST-SSH-PASSWORD"]; ok {
		t.Error("PasswordAuthentication is no globally")
	}
	for _, unexpected := range []string{"VNX-HOST-PERM-PASSWD", "VNX-HOST-KUBELET-AUTHZ"} {
		if _, ok := got[unexpected]; ok {
			t.Errorf("%s should pass", unexpected)
		}
	}

	if _, ok := ids(Run(root, "eks-node"))["VNX-HOST-FORWARD"]; ok {
		t.Error("a Kubernetes node needs IP forwarding; it is not a finding there")
	}
}

func TestAnUnreadableHostReportsNothing(t *testing.T) {
	if got := Run(t.TempDir(), "ec2"); len(got) != 0 {
		t.Fatalf("a missing file is not a failing setting: %+v", got)
	}
}

func TestSSHDefaults(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/ssh/sshd_config", "# all defaults\n", 0o644)
	got := ids(Run(root, "ec2"))
	if got["VNX-HOST-SSH-ROOT"].Detail != "PermitRootLogin is prohibit-password (the default)" {
		t.Fatalf("root = %+v", got["VNX-HOST-SSH-ROOT"])
	}
	if _, ok := got["VNX-HOST-SSH-PASSWORD"]; !ok {
		t.Fatal("password login is on by default")
	}
}
