//go:build linux

package lsmguard

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
)

// The embedded object is a valid LSM program for bprm_check_security with the
// maps the Go side uses, and their key and value sizes match. Loading it into
// the kernel needs privileges and is not done here.
func TestEmbeddedProgramIsAnExecGuard(t *testing.T) {
	spec, err := Spec()
	if err != nil {
		t.Fatal(err)
	}
	p := spec.Programs["vulnetix_exec_guard"]
	if p == nil || p.Type != ebpf.LSM || p.AttachTo != "bprm_check_security" {
		t.Fatalf("program = %+v", p)
	}
	blocked := spec.Maps["blocked"]
	if blocked == nil || blocked.KeySize != 16 || blocked.ValueSize != 4 {
		t.Fatalf("blocked map = %+v", blocked)
	}
	if spec.Maps["enforce"] == nil || spec.Maps["events"] == nil || spec.Maps["events"].Type != ebpf.RingBuf {
		t.Fatal("enforce and events maps are missing")
	}
}

func TestStatKeyNamesARegularFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "x")
	if err := os.WriteFile(f, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	k, ok := statKey(f)
	var st syscall.Stat_t
	_ = syscall.Stat(f, &st)
	if !ok || k.Ino != st.Ino {
		t.Fatalf("key = %+v, ok = %v", k, ok)
	}
	if _, ok := statKey(dir); ok {
		t.Fatal("a directory is not a program")
	}
	if _, ok := statKey(filepath.Join(dir, "missing")); ok {
		t.Fatal("a missing file has no key")
	}
}

func TestLoadAndRefuseWhenPrivileged(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading a BPF LSM program needs root")
	}
	g, err := Load()
	if err != nil {
		t.Skipf("BPF LSM not available: %v", err)
	}
	defer g.Close()
	if err := g.SetEnforce(true); err != nil {
		t.Fatal(err)
	}
}
