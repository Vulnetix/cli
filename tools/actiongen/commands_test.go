package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The vex input is one path or URL per line, each passed as its own --vex, with
// blank lines and surrounding space dropped and no word splitting or globbing.
func TestVexInputBecomesRepeatedFlags(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	lib, err := filepath.Abs(filepath.Join("..", "..", "action-lib", "commands.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := `. "$1"; vx_build "$2" || exit 3; printf '%s\n' "${cmd[@]}"`
	for _, action := range []string{"sca", "sast", "secrets", "iac", "containers"} {
		c := exec.Command("bash", "-c", script, "bash", lib, action)
		c.Env = append(c.Environ(), "VX_IN_VEX=  vex/a.json \n\n https://example.com/b.json\n*.json\n")
		out, err := c.Output()
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		got := strings.Split(strings.TrimSpace(string(out)), "\n")
		want := []string{action, "--vex", "vex/a.json", "--vex", "https://example.com/b.json", "--vex", "*.json"}
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s: got %q, want %q", action, got, want)
		}
	}
}
