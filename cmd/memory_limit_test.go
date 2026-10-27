package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanMemoryLimit(t *testing.T) {
	const gib = int64(1) << 30
	cases := []struct {
		name          string
		env           bool
		cgroup, total int64
		want          int64
	}{
		{"GOMEMLIMIT set wins", true, 4 * gib, 8 * gib, 0},
		{"physical memory only", false, 0, 8 * gib, 6 * gib},
		{"a smaller cgroup limit wins", false, 2 * gib, 8 * gib, 3 * gib / 2},
		{"a cgroup above physical memory does not raise it", false, 64 * gib, 8 * gib, 6 * gib},
		{"cgroup only", false, 4 * gib, 0, 3 * gib},
		{"nothing known", false, 0, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := scanMemoryLimit(c.env, c.cgroup, c.total); got != c.want {
				t.Fatalf("scanMemoryLimit = %d, want %d", got, c.want)
			}
		})
	}
}

func TestCgroupLimit(t *testing.T) {
	root := t.TempDir()
	write := func(rel, v string) {
		dir := filepath.Join(root, rel)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("system.slice/github-runner.service", "8589934592\n")
	write("user.slice", "max\n")

	if got := cgroupLimit("0::/system.slice/github-runner.service\n", root); got != 8589934592 {
		t.Errorf("limited cgroup = %d", got)
	}
	if got := cgroupLimit("0::/user.slice\n", root); got != 0 {
		t.Errorf(`"max" must read as no limit, got %d`, got)
	}
	if got := cgroupLimit("12:memory:/legacy\n", root); got != 0 {
		t.Errorf("a v1-only hierarchy must read as no limit, got %d", got)
	}
}
