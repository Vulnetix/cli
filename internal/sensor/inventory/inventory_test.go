package inventory

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/vulnetix/cli/v4/internal/binpkg"
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

func TestProcessCountIsTheTrueNumber(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < listCap+5; i++ {
		proc(t, root, strconv.Itoa(1000+i), "/usr/bin/bash",
			"55d0-55d1 r-xp 00000000 fd:01 11 /usr/bin/bash\n7f00-7f01 r-xp 00000000 fd:01 12 /usr/bin/bash\n")
	}
	res := Scan(root, binpkg.OwnerIndex{"/usr/bin/bash": {Name: "bash", Version: "5.2", Ecosystem: "deb"}})
	if len(res.Packages) != 1 {
		t.Fatalf("packages = %+v", res.Packages)
	}
	if p := res.Packages[0]; p.ProcessCount != listCap+5 || len(p.Processes) != listCap {
		t.Errorf("count = %d examples = %d; want every process counted once and %d examples", p.ProcessCount, len(p.Processes), listCap)
	}
}

func nsLink(t *testing.T, root, pid, ns string) {
	t.Helper()
	dir := filepath.Join(root, "proc", pid, "ns")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ns, filepath.Join(dir, "mnt")); err != nil {
		t.Fatal(err)
	}
}

func TestContainerProcessesAreCountedNotMatched(t *testing.T) {
	root := t.TempDir()
	proc(t, root, "1", "/usr/lib/systemd/systemd", "55d0-55d1 r-xp 00000000 fd:01 11 /usr/bin/bash\n")
	proc(t, root, "20", "/usr/bin/bash", "55d0-55d1 r-xp 00000000 fd:01 11 /usr/bin/bash\n")
	// A container's own bash: the same path, another root.
	proc(t, root, "30", "/usr/bin/bash", "55d0-55d1 r-xp 00000000 fd:01 11 /usr/bin/bash\n")
	nsLink(t, root, "1", "mnt:[4026531841]")
	nsLink(t, root, "20", "mnt:[4026531841]")
	nsLink(t, root, "30", "mnt:[4026532999]")
	res := Scan(root, binpkg.OwnerIndex{"/usr/bin/bash": {Name: "bash", Version: "5.2", Ecosystem: "deb"}})
	if res.Unattributed != 1 {
		t.Fatalf("unattributed = %d, want the container process", res.Unattributed)
	}
	if len(res.Packages) != 1 || res.Packages[0].ProcessCount != 2 {
		t.Fatalf("packages = %+v; only host processes count", res.Packages)
	}
}

func TestRenamedLibraryIsStillStaleLoaded(t *testing.T) {
	root := t.TempDir()
	// The process still maps libssl.so.3.0.11, which the upgrade replaced with
	// libssl.so.3.0.15.
	if err := os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr/lib/libssl.so.3.0.15"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	proc(t, root, "40", "/usr/sbin/nginx", "7f00-7f01 r-xp 00000000 fd:01 12 /usr/lib/libssl.so.3.0.11 (deleted)\n")
	want := MappedPaths(root)
	if !want["/usr/lib/libssl.so.3.0.15"] {
		t.Fatalf("mapped paths %v must ask the index about the renamed library", want)
	}
	res := Scan(root, binpkg.OwnerIndex{"/usr/lib/libssl.so.3.0.15": {Name: "openssl", Version: "3.0.15-1", Ecosystem: "arch"}})
	if len(res.Packages) != 1 || res.Packages[0].Name != "openssl" || res.Packages[0].State != StaleLoaded {
		t.Fatalf("packages = %+v, want openssl stale-loaded", res.Packages)
	}
}
