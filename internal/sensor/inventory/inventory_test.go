package inventory

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vulnetix/cli/v3/internal/binpkg"
)

func proc(t *testing.T, root string, pid, exe, maps string) {
	t.Helper()
	dir := filepath.Join(root, "proc", pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "maps"), []byte(maps), 0o644); err != nil {
		t.Fatal(err)
	}
	if exe != "" {
		if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestScanFindsLoadedStaleAndFileless(t *testing.T) {
	root := t.TempDir()
	proc(t, root, "100", "/usr/sbin/nginx",
		"55d0-55d1 r-xp 00000000 fd:01 11 /usr/sbin/nginx\n"+
			"7f00-7f01 r-xp 00000000 fd:01 12 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n"+
			"7f02-7f03 r--p 00000000 fd:01 13 /usr/lib/x86_64-linux-gnu/libz.so.1\n"+
			"7f04-7f05 rw-p 00000000 00:00 0 \n"+
			"7ffd-7ffe rw-p 00000000 00:00 0 [stack]\n")
	proc(t, root, "200", "/tmp/.cache/x",
		"5600-5601 r-xp 00000000 fd:01 21 /tmp/.cache/x\n"+
			"7f10-7f11 r-xp 00000000 00:01 22 /memfd:payload (deleted)\n"+
			"7f12-7f13 r-xp 00000000 fd:01 23 /opt/my app/lib.so\n")
	if err := os.MkdirAll(filepath.Join(root, "proc", "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "proc", "300"), 0o755); err != nil {
		t.Fatal(err) // a process with no readable maps
	}

	idx := binpkg.OwnerIndex{
		"/usr/sbin/nginx":                       {Name: "nginx", Version: "1.24.0-2", Ecosystem: "deb"},
		"/usr/lib/x86_64-linux-gnu/libssl.so.3": {Name: "libssl3", Version: "3.0.11-1", Ecosystem: "deb"},
		"/lib/x86_64-linux-gnu/libz.so.1":       {Name: "zlib1g", Version: "1:1.2.13", Ecosystem: "deb"},
	}
	res := Scan(root, idx)

	if res.Processes != 3 || res.Unreadable != 1 {
		t.Fatalf("processes = %d unreadable = %d", res.Processes, res.Unreadable)
	}
	states := map[string]string{}
	for _, p := range res.Packages {
		states[p.Name] = p.State
	}
	if states["libssl3"] != StaleLoaded {
		t.Errorf("a deleted mapping means the process runs replaced code: %v", states)
	}
	if states["nginx"] != Loaded || states["zlib1g"] != Loaded {
		t.Errorf("states = %v (zlib is found through the merged-/usr twin)", states)
	}
	if res.Packages[0].Name != "libssl3" {
		t.Error("stale-loaded packages sort first: they need a restart")
	}
	if len(res.MemfdExec) != 1 || res.MemfdExec[0].PID != 200 {
		t.Fatalf("memfd exec = %+v", res.MemfdExec)
	}
	if len(res.Unowned) != 2 || res.Unowned[0] != "/opt/my app/lib.so" || res.Unowned[1] != "/tmp/.cache/x" {
		t.Fatalf("unowned = %v (a path with a space is read whole)", res.Unowned)
	}
}

func TestMappedPath(t *testing.T) {
	path, perms, ok := mappedPath("7f00-7f01 r-xp 00000000 fd:01 12    /usr/lib/a b.so (deleted)")
	if !ok || path != "/usr/lib/a b.so (deleted)" || perms != "r-xp" {
		t.Fatalf("got %q %q %v", path, perms, ok)
	}
	if _, _, ok := mappedPath("7f00-7f01 rw-p 00000000 00:00 0"); ok {
		t.Fatal("an anonymous mapping has no path")
	}
}
