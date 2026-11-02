package sast

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The vectors are github/codeql-action's own (src/fingerprints.test.ts), so a
// hash computed here matches the one GitHub's upload step would compute.
func TestLineHashesMatchCodeQLAction(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"empty", "", []string{"c129715d7a2bc9a3:1"}},
		{"newlines", " a\nb\n  \t\tc\n d", []string{
			"271789c17abda88f:1", "54703d4cd895b18:1", "180aee12dab6264:1", "a23a3dc5e078b07b:1",
		}},
		{"no trailing newline", " hello; \t\nworld!!!\n\n\n  \t\tGreetings\n End", []string{
			"8b7cf3e952e7aeb2:1", "b1ae1287ec4718d9:1", "bff680108adb0fcc:1",
			"c6805c5e1288b612:1", "b86d3392aea1be30:1", "e6ceba753e1a442:1",
		}},
		{"lf", " hello; \t\nworld!!!\n\n\n  \t\tGreetings\n End\n", trailing},
		{"cr", " hello; \t\nworld!!!\r\r\r  \t\tGreetings\r End\r", trailing},
		{"crlf", " hello; \t\r\nworld!!!\r\n\r\n\r\n  \t\tGreetings\r\n End\r\n", trailing},
		{"mixed", " hello; \t\nworld!!!\r\n\n\r  \t\tGreetings\r End\r\n", trailing},
		{"repeated", strings.Repeat("Lorem ipsum dolor sit amet.\n", 10), []string{
			"a7f2ff13bc495cf2:1", "a7f2ff13bc495cf2:2", "a7f2ff13bc495cf2:3",
			"a7f2ff13bc495cf2:4", "a7f2ff13bc495cf2:5", "a7f2ff13bc495cf2:6",
			"a7f2ff1481e87703:1", "a9cf91f7bbf1862b:1", "55ec222b86bcae53:1",
			"cc97dc7b1d7d8f7b:1", "c129715d7a2bc9a3:1",
		}},
		{"code", "x = 2\nx = 1\nprint(x)\nx = 3\nprint(x)\nx = 4\nprint(x)\n", []string{
			"e54938cc54b302f1:1", "bb609acbe9138d60:1", "1131fd5871777f34:1",
			"5c482a0f8b35ea28:1", "54517377da7028d2:1", "2c644846cb18d53e:1",
			"f1b89f20de0d133:1", "c129715d7a2bc9a3:1",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := LineHashes([]byte(tc.input))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("LineHashes(%q)\n got %v\nwant %v", tc.input, got, tc.want)
			}
		})
	}
}

var trailing = []string{
	"e9496ae3ebfced30:1", "fb7c023a8b9ccb3f:1", "ce8ba1a563dcdaca:1",
	"e20e36e16fcb0cc8:1", "b3edc88f2938467e:1", "c8e28b0b4002a3a0:1",
	"c129715d7a2bc9a3:1",
}

func TestLineHashCache(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.py")
	if err := os.WriteFile(p, []byte("x = 2\nx = 1\nprint(x)\nx = 3\nprint(x)\nx = 4\nprint(x)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := NewLineHashCache()
	if got := c.Hash(p, 3); got != "1131fd5871777f34:1" {
		t.Fatalf("line 3 = %q", got)
	}
	if got := c.Hash(p, 0); got != "e54938cc54b302f1:1" {
		t.Fatalf("whole file hashes line 1, got %q", got)
	}
	if got := c.Hash(p, 99); got != "" {
		t.Fatalf("missing line = %q", got)
	}
	if got := c.Hash(filepath.Join(dir, "missing"), 1); got != "" {
		t.Fatalf("missing file = %q", got)
	}
}
